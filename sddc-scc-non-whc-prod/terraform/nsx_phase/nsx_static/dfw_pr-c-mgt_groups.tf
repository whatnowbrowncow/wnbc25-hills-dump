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

resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-130" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-130"
  description  = "role: pr-c-mgt_ip_10-120-163-130, ip: [10.120.163.130]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.130"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-136" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-136"
  description  = "role: pr-c-mgt_ip_10-120-163-136, ip: [10.120.163.136]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.136"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-99-23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-99-23"
  description  = "role: pr-c-mgt_ip_10-120-99-23, ip: [10.120.99.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-99-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-99-24"
  description  = "role: pr-c-mgt_ip_10-120-99-24, ip: [10.120.99.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-66-92" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-66-92"
  description  = "role: pr-c-mgt_ip_10-120-66-92, ip: [10.120.66.92]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.66.92"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-66-93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-66-93"
  description  = "role: pr-c-mgt_ip_10-120-66-93, ip: [10.120.66.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.66.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-141-41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-141-41"
  description  = "role: pr-c-mgt_ip_10-120-141-41, ip: [10.120.141.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-141-42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-141-42"
  description  = "role: pr-c-mgt_ip_10-120-141-42, ip: [10.120.141.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-141-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-141-43"
  description  = "role: pr-c-mgt_ip_10-120-141-43, ip: [10.120.141.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-141-44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-141-44"
  description  = "role: pr-c-mgt_ip_10-120-141-44, ip: [10.120.141.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-129-220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-129-220"
  description  = "role: pr-c-mgt_ip_10-210-129-220, ip: [10.210.129.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-129-70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-129-70"
  description  = "role: pr-c-mgt_ip_10-210-129-70, ip: [10.210.129.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-129-52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-129-52"
  description  = "role: pr-c-mgt_ip_10-210-129-52, ip: [10.210.129.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-129-250" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-129-250"
  description  = "role: pr-c-mgt_ip_10-210-129-250, ip: [10.210.129.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.250"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-129-250" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-129-250"
  description  = "role: pr-c-mgt_ip_10-180-129-250, ip: [10.180.129.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.250"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-129-52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-129-52"
  description  = "role: pr-c-mgt_ip_10-180-129-52, ip: [10.180.129.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-129-220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-129-220"
  description  = "role: pr-c-mgt_ip_10-180-129-220, ip: [10.180.129.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-129-221" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-129-221"
  description  = "role: pr-c-mgt_ip_10-180-129-221, ip: [10.180.129.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-0-0s16"
  description  = "role: pr-c-mgt_ip_10-120-0-0s16, ip: [10.120.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-141-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-141-0s24"
  description  = "role: pr-c-mgt_ip_10-120-141-0s24, ip: [10.120.141.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-0s24"
  description  = "role: pr-c-mgt_ip_10-120-163-0s24, ip: [10.120.163.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-129-0s24"
  description  = "role: pr-c-mgt_ip_10-180-129-0s24, ip: [10.180.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-129-0s24"
  description  = "role: pr-c-mgt_ip_10-120-129-0s24, ip: [10.120.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-129-0s24"
  description  = "role: pr-c-mgt_ip_10-210-129-0s24, ip: [10.210.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-99-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-99-0s24"
  description  = "role: pr-c-mgt_ip_10-1-99-0s24, ip: [10.1.99.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.99.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_192-168-1-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_192-168-1-0s24"
  description  = "role: pr-c-mgt_ip_192-168-1-0s24, ip: [192.168.1.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.1.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_192-168-10-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_192-168-10-0s24"
  description  = "role: pr-c-mgt_ip_192-168-10-0s24, ip: [192.168.10.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.10.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-211-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-211-129-0s24"
  description  = "role: pr-c-mgt_ip_10-211-129-0s24, ip: [10.211.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.211.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-212-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-212-129-0s24"
  description  = "role: pr-c-mgt_ip_10-212-129-0s24, ip: [10.212.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.212.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-213-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-213-129-0s24"
  description  = "role: pr-c-mgt_ip_10-213-129-0s24, ip: [10.213.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.213.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-214-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-214-129-0s24"
  description  = "role: pr-c-mgt_ip_10-214-129-0s24, ip: [10.214.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.214.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-215-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-215-129-0s24"
  description  = "role: pr-c-mgt_ip_10-215-129-0s24, ip: [10.215.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.215.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-216-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-216-129-0s24"
  description  = "role: pr-c-mgt_ip_10-216-129-0s24, ip: [10.216.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.216.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-125-4-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-125-4-0s22"
  description  = "role: pr-c-mgt_ip_10-125-4-0s22, ip: [10.125.4.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.4.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-125-20-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-125-20-0s24"
  description  = "role: pr-c-mgt_ip_10-125-20-0s24, ip: [10.125.20.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.20.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-125-4-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-125-4-0s24"
  description  = "role: pr-c-mgt_ip_10-125-4-0s24, ip: [10.125.4.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.4.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-125-8-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-125-8-0s24"
  description  = "role: pr-c-mgt_ip_10-125-8-0s24, ip: [10.125.8.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.8.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-126-44-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-126-44-0s22"
  description  = "role: pr-c-mgt_ip_10-126-44-0s22, ip: [10.126.44.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.44.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-156-4-0s25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-156-4-0s25"
  description  = "role: pr-c-mgt_ip_10-156-4-0s25, ip: [10.156.4.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.4.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-156-4-128s25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-156-4-128s25"
  description  = "role: pr-c-mgt_ip_10-156-4-128s25, ip: [10.156.4.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.4.128/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-0s24"
  description  = "role: pr-c-mgt_ip_10-120-140-0s24, ip: [10.120.140.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-64s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-64s27"
  description  = "role: pr-c-mgt_ip_10-120-143-64s27, ip: [10.120.143.64/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.64/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-0-0-0s8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-0-0-0s8"
  description  = "role: pr-c-mgt_ip_10-0-0-0s8, ip: [10.0.0.0/8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.0.0.0/8"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-134-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-134-0s24"
  description  = "role: pr-c-mgt_ip_10-120-134-0s24, ip: [10.120.134.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_192-168-2-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_192-168-2-0s23"
  description  = "role: pr-c-mgt_ip_192-168-2-0s23, ip: [192.168.2.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-0s24"
  description  = "role: pr-c-mgt_ip_10-120-131-0s24, ip: [10.120.131.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-80-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-80-0s24"
  description  = "role: pr-c-mgt_ip_10-120-80-0s24, ip: [10.120.80.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.80.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-130-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-130-0s24"
  description  = "role: pr-c-mgt_ip_10-120-130-0s24, ip: [10.120.130.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-139-224s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-139-224s27"
  description  = "role: pr-c-mgt_ip_10-120-139-224s27, ip: [10.120.139.224/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.139.224/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-160s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-160s27"
  description  = "role: pr-c-mgt_ip_10-120-143-160s27, ip: [10.120.143.160/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.160/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_172-16-0-0s12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_172-16-0-0s12"
  description  = "role: pr-c-mgt_ip_172-16-0-0s12, ip: [172.16.0.0/12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.16.0.0/12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_192-168-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_192-168-0-0s16"
  description  = "role: pr-c-mgt_ip_192-168-0-0s16, ip: [192.168.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-194-0s26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-194-0s26"
  description  = "role: pr-c-mgt_ip_10-120-194-0s26, ip: [10.120.194.0/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.0/26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-242-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-242-0s24"
  description  = "role: pr-c-mgt_ip_10-120-242-0s24, ip: [10.120.242.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.242.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-146-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-146-0s24"
  description  = "role: pr-c-mgt_ip_10-120-146-0s24, ip: [10.120.146.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-22-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-22-0s24"
  description  = "role: pr-c-mgt_ip_10-1-22-0s24, ip: [10.1.22.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-82-128s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-82-128s27"
  description  = "role: pr-c-mgt_ip_10-1-82-128s27, ip: [10.1.82.128/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.128/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-0s29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-0s29"
  description  = "role: pr-c-mgt_ip_10-1-83-0s29, ip: [10.1.83.0/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.0/29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-64s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-64s27"
  description  = "role: pr-c-mgt_ip_10-1-83-64s27, ip: [10.1.83.64/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.64/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-194-140-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-194-140-0s24"
  description  = "role: pr-c-mgt_ip_10-194-140-0s24, ip: [10.194.140.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.194.140.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-126-204-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-126-204-0s22"
  description  = "role: pr-c-mgt_ip_10-126-204-0s22, ip: [10.126.204.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.204.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-126-236-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-126-236-0s22"
  description  = "role: pr-c-mgt_ip_10-126-236-0s22, ip: [10.126.236.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.236.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-126-252-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-126-252-0s22"
  description  = "role: pr-c-mgt_ip_10-126-252-0s22, ip: [10.126.252.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.252.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-156-2-0s25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-156-2-0s25"
  description  = "role: pr-c-mgt_ip_10-156-2-0s25, ip: [10.156.2.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.2.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-156-2-128s25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-156-2-128s25"
  description  = "role: pr-c-mgt_ip_10-156-2-128s25, ip: [10.156.2.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.2.128/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-156-3-0s25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-156-3-0s25"
  description  = "role: pr-c-mgt_ip_10-156-3-0s25, ip: [10.156.3.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.3.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-126-193-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-126-193-0s24"
  description  = "role: pr-c-mgt_ip_10-126-193-0s24, ip: [10.126.193.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.193.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-126-194-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-126-194-0s24"
  description  = "role: pr-c-mgt_ip_10-126-194-0s24, ip: [10.126.194.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.194.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-126-76-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-126-76-0s22"
  description  = "role: pr-c-mgt_ip_10-126-76-0s22, ip: [10.126.76.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.76.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-156-0-128s25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-156-0-128s25"
  description  = "role: pr-c-mgt_ip_10-156-0-128s25, ip: [10.156.0.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.0.128/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-128-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-128-0s24"
  description  = "role: pr-c-mgt_ip_10-120-128-0s24, ip: [10.120.128.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.128.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-132-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-132-0s24"
  description  = "role: pr-c-mgt_ip_10-120-132-0s24, ip: [10.120.132.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-133-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-133-0s24"
  description  = "role: pr-c-mgt_ip_10-120-133-0s24, ip: [10.120.133.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.133.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-135-0s25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-135-0s25"
  description  = "role: pr-c-mgt_ip_10-120-135-0s25, ip: [10.120.135.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.135.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-136-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-136-0s24"
  description  = "role: pr-c-mgt_ip_10-120-136-0s24, ip: [10.120.136.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-137-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-137-0s24"
  description  = "role: pr-c-mgt_ip_10-120-137-0s24, ip: [10.120.137.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.137.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-128s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-128s27"
  description  = "role: pr-c-mgt_ip_10-120-143-128s27, ip: [10.120.143.128/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.128/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-96s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-96s27"
  description  = "role: pr-c-mgt_ip_10-120-143-96s27, ip: [10.120.143.96/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.96/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-160-160s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-160-160s27"
  description  = "role: pr-c-mgt_ip_10-120-160-160s27, ip: [10.120.160.160/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.160.160/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_100-78-51-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_100-78-51-0s24"
  description  = "role: pr-c-mgt_ip_100-78-51-0s24, ip: [100.78.51.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.78.51.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_100-78-52-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_100-78-52-0s24"
  description  = "role: pr-c-mgt_ip_100-78-52-0s24, ip: [100.78.52.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.78.52.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_100-78-53-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_100-78-53-0s24"
  description  = "role: pr-c-mgt_ip_100-78-53-0s24, ip: [100.78.53.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.78.53.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-156-3-128s25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-156-3-128s25"
  description  = "role: pr-c-mgt_ip_10-156-3-128s25, ip: [10.156.3.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.3.128/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-156-5-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-156-5-0s24"
  description  = "role: pr-c-mgt_ip_10-156-5-0s24, ip: [10.156.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-0-0s16"
  description  = "role: pr-c-mgt_ip_10-210-0-0s16, ip: [10.210.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-0-0s16"
  description  = "role: pr-c-mgt_ip_10-180-0-0s16, ip: [10.180.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-112-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-112-0-0s16"
  description  = "role: pr-c-mgt_ip_10-112-0-0s16, ip: [10.112.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-19-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-19-0-0s16"
  description  = "role: pr-c-mgt_ip_10-19-0-0s16, ip: [10.19.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-121-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-121-0-0s16"
  description  = "role: pr-c-mgt_ip_10-121-0-0s16, ip: [10.121.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_100-79-0-0s17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_100-79-0-0s17"
  description  = "role: pr-c-mgt_ip_100-79-0-0s17, ip: [100.79.0.0/17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.0.0/17"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-193-30-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-193-30-0s24"
  description  = "role: pr-c-mgt_ip_10-193-30-0s24, ip: [10.193.30.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.193.30.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-194-20-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-194-20-0s24"
  description  = "role: pr-c-mgt_ip_10-194-20-0s24, ip: [10.194.20.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.194.20.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-126-225-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-126-225-0s24"
  description  = "role: pr-c-mgt_ip_10-126-225-0s24, ip: [10.126.225.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.225.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-126-226-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-126-226-0s24"
  description  = "role: pr-c-mgt_ip_10-126-226-0s24, ip: [10.126.226.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.226.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-126-241-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-126-241-0s24"
  description  = "role: pr-c-mgt_ip_10-126-241-0s24, ip: [10.126.241.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.241.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-126-242-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-126-242-0s24"
  description  = "role: pr-c-mgt_ip_10-126-242-0s24, ip: [10.126.242.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.242.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_192-168-48-0s20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_192-168-48-0s20"
  description  = "role: pr-c-mgt_ip_192-168-48-0s20, ip: [192.168.48.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.48.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_192-168-12-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_192-168-12-0s22"
  description  = "role: pr-c-mgt_ip_192-168-12-0s22, ip: [192.168.12.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.12.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_192-168-16-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_192-168-16-0s22"
  description  = "role: pr-c-mgt_ip_192-168-16-0s22, ip: [192.168.16.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.16.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-30-200-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-30-200-0s24"
  description  = "role: pr-c-mgt_ip_10-30-200-0s24, ip: [10.30.200.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.30.200.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-30-202-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-30-202-0s24"
  description  = "role: pr-c-mgt_ip_10-30-202-0s24, ip: [10.30.202.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.30.202.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-40-200-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-40-200-0s24"
  description  = "role: pr-c-mgt_ip_10-40-200-0s24, ip: [10.40.200.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.200.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-40-202-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-40-202-0s24"
  description  = "role: pr-c-mgt_ip_10-40-202-0s24, ip: [10.40.202.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.202.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-130-200-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-130-200-0s23"
  description  = "role: pr-c-mgt_ip_10-130-200-0s23, ip: [10.130.200.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.130.200.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-191-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-191-0-0s16"
  description  = "role: pr-c-mgt_ip_10-191-0-0s16, ip: [10.191.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.191.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-193-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-193-0-0s16"
  description  = "role: pr-c-mgt_ip_10-193-0-0s16, ip: [10.193.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.193.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-195-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-195-0-0s16"
  description  = "role: pr-c-mgt_ip_10-195-0-0s16, ip: [10.195.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.195.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-201-224-0s20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-201-224-0s20"
  description  = "role: pr-c-mgt_ip_10-201-224-0s20, ip: [10.201.224.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.224.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-208-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-208-0-0s16"
  description  = "role: pr-c-mgt_ip_10-208-0-0s16, ip: [10.208.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.208.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-241-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-241-0-0s16"
  description  = "role: pr-c-mgt_ip_10-241-0-0s16, ip: [10.241.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.241.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-242-10-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-242-10-0s24"
  description  = "role: pr-c-mgt_ip_10-242-10-0s24, ip: [10.242.10.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.242.10.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-116-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-116-0-0s16"
  description  = "role: pr-c-mgt_ip_10-116-0-0s16, ip: [10.116.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.116.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-122-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-122-0-0s16"
  description  = "role: pr-c-mgt_ip_10-122-0-0s16, ip: [10.122.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-181-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-181-0-0s16"
  description  = "role: pr-c-mgt_ip_10-181-0-0s16, ip: [10.181.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.181.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-cde-jumphost-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-cde-jumphost-lan"
  description  = "role: pr-c-mgt_sc1-cde-jumphost-lan, ip: [10.120.141.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-cx-cde-nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-cx-cde-nets"
  description  = "role: CHG0068990, ip: [10.121.0.0/18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.0.0/18"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-prd-ncde-sports-app-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-prd-ncde-sports-app-lan"
  description  = "role: CHG0120371, ip: [10.121.68.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.68.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-inv-cde-nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-inv-cde-nets"
  description  = "role: pr-c-mgt_sc1-inv-cde-nets, ip: [10.122.0.0/18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.0.0/18"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_inv-cde-mgmt-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_inv-cde-mgmt-lan"
  description  = "role: pr-c-mgt_inv-cde-mgmt-lan, ip: [10.122.10.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.10.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_invxpup06mst001-inv-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_invxpup06mst001-inv-williamhill-plc"
  description  = "role: pr-c-mgt_invxpup06mst001-inv-williamhill-plc, ip: [10.122.10.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.10.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_aws-ddos-big-ip-net" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_aws-ddos-big-ip-net"
  description  = "role: pr-c-mgt_aws-ddos-big-ip-net, ip: [10.125.0.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprtdb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprtdb001"
  description  = "role: CHG0123808, ip: [10.120.177.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.177.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-120-141-40s29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-120-141-40s29"
  description  = "role: CHG0123933, ip: [10.120.141.40/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.40/29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_us-njp-ddos-platform" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_us-njp-ddos-platform"
  description  = "role: CHG0126265, ip: [10.125.20.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.20.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_aws-ddos-dev-100-78-80-0s20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_aws-ddos-dev-100-78-80-0s20"
  description  = "role: CHG0142649, ip: [100.78.80.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.78.80.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_service-mgmt-scc-whc-prod-sddc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_service-mgmt-scc-whc-prod-sddc"
  description  = "role: pr-c-mgt_service-mgmt-scc-whc-prod-sddc, ip: [10.156.3.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.3.128/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprein01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprein01"
  description  = "role: pr-c-mgt_sc1apprein01, ip: [10.120.140.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprein02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprein02"
  description  = "role: pr-c-mgt_sc1apprein02, ip: [10.120.140.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprein03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprein03"
  description  = "role: pr-c-mgt_sc1apprein03, ip: [10.120.140.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprein07" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprein07"
  description  = "role: pr-c-mgt_sc1apprein07, ip: [10.120.140.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprein08" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprein08"
  description  = "role: pr-c-mgt_sc1apprein08, ip: [10.120.140.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprein09" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprein09"
  description  = "role: pr-c-mgt_sc1apprein09, ip: [10.120.140.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprein10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprein10"
  description  = "role: pr-c-mgt_sc1apprein10, ip: [10.120.140.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprein11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprein11"
  description  = "role: pr-c-mgt_sc1apprein11, ip: [10.120.140.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.207"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprein12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprein12"
  description  = "role: pr-c-mgt_sc1apprein12, ip: [10.120.140.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprein13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprein13"
  description  = "role: pr-c-mgt_sc1apprein13, ip: [10.120.140.209]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.209"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprein14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprein14"
  description  = "role: CHG0140052, ip: [10.120.140.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-bgr-clt-pc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-bgr-clt-pc1"
  description  = "role: CHG0120371, ip: [10.120.141.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-bgr-clt-pc2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-bgr-clt-pc2"
  description  = "role: CHG0120371, ip: [10.120.141.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-bgr-clt-pc3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-bgr-clt-pc3"
  description  = "role: CHG0120371, ip: [10.120.141.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-bgr-clt-pc4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-bgr-clt-pc4"
  description  = "role: CHG0120371, ip: [10.120.141.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_inv-cde-int-pres-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_inv-cde-int-pres-lan"
  description  = "role: CHG0066592, ip: [10.122.4.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.4.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_inv-cde-api-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_inv-cde-api-lan"
  description  = "role: CHG0066592, ip: [10.122.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_inv-cde-ext-pres-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_inv-cde-ext-pres-lan"
  description  = "role: CHG0066592, ip: [10.122.6.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.6.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_inv-fe-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_inv-fe-tier"
  description  = "role: CHG0066592, ip: [10.120.140.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_inv-cde-lan01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_inv-cde-lan01"
  description  = "role: CHG0071650, ip: [10.122.7.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.7.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_inv-ncde-lan01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_inv-ncde-lan01"
  description  = "role: CHG0071650, ip: [10.121.7.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.7.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprncp005" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprncp005"
  description  = "role: CHG0146032, ip: [10.120.99.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprncp005-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprncp005-vmc"
  description  = "role: CHG0146032, ip: [10.120.104.6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.6"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprncp006" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprncp006"
  description  = "role: CHG0146032, ip: [10.120.99.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprncp006-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprncp006-vmc"
  description  = "role: pr-c-mgt_sc1wnprncp006-vmc, ip: [10.120.104.7]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.7"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_brs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_brs"
  description  = "role: pr-c-mgt_vsphere_mgmt_net_brs, ip: [10.210.134.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.134.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_scc"
  description  = "role: pr-c-mgt_vsphere_mgmt_net_scc, ip: [10.120.134.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_gib" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_gib"
  description  = "role: pr-c-mgt_vsphere_mgmt_net_gib, ip: [10.180.138.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.138.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_sof" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_sof"
  description  = "role: pr-c-mgt_vsphere_mgmt_net_sof, ip: [10.53.96.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.96.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_dat" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_dat"
  description  = "role: Bulgaira Daticum VMware net, ip: [10.54.98.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.54.98.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_pp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_pp"
  description  = "role: pr-c-mgt_vsphere_mgmt_net_pp, ip: [10.201.226.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.226.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_stj" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_stj"
  description  = "role: pr-c-mgt_vsphere_mgmt_net_stj, ip: [10.110.134.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.110.134.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_kra" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_kra"
  description  = "role: pr-c-mgt_vsphere_mgmt_net_kra, ip: [10.55.7.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.7.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_ld6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_ld6"
  description  = "role: pr-c-mgt_vsphere_mgmt_net_ld6, ip: [10.112.8.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.8.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_man" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_man"
  description  = "role: pr-c-mgt_vsphere_mgmt_net_man, ip: [10.123.198.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.198.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_hci_stj" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_hci_stj"
  description  = "role: pr-c-mgt_vsphere_mgmt_net_hci_stj, ip: [10.8.1.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.8.1.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_brs_hci" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_brs_hci"
  description  = "role: pr-c-mgt_vsphere_mgmt_net_brs_hci, ip: [10.210.10.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.10.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_mal" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_mal"
  description  = "role: pr-c-mgt_vsphere_mgmt_net_mal, ip: [10.129.8.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.8.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_us-nj-10-174-104-0" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_us-nj-10-174-104-0"
  description  = "role: pr-c-mgt_us-nj-10-174-104-0, ip: [10.174.104.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.174.104.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_nj2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_nj2"
  description  = "role: CHG0133793, ip: [10.174.119.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.174.119.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vsphere_mgmt_net_us-in1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vsphere_mgmt_net_us-in1"
  description  = "role: CHG0135610, ip: [10.174.135.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.174.135.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprcmg41-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprcmg41-prod-williamhill-plc"
  description  = "role: CHG0114077, ip: [10.120.141.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprcmg42-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprcmg42-prod-williamhill-plc"
  description  = "role: CHG0114077, ip: [10.120.141.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprcmg43-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprcmg43-prod-williamhill-plc"
  description  = "role: CHG0114077, ip: [10.120.141.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprcmg44-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprcmg44-prod-williamhill-plc"
  description  = "role: CHG0114077, ip: [10.120.141.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcmg31-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcmg31-prod-williamhill-plc"
  description  = "role: CHG0114077, ip: [10.120.141.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcmg32-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcmg32-prod-williamhill-plc"
  description  = "role: CHG0114077, ip: [10.120.141.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcmg33-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcmg33-prod-williamhill-plc"
  description  = "role: CHG0114077, ip: [10.120.141.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcmg34-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcmg34-prod-williamhill-plc"
  description  = "role: CHG0114077, ip: [10.120.141.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-99-254-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-99-254-0slash24"
  description  = "role: pr-c-mgt_10-99-254-0slash24, ip: [10.99.254.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.99.254.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-55-99-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-55-99-0slash24"
  description  = "role: CHG0120144, ip: [10.55.99.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.99.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-56-99-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-56-99-0slash24"
  description  = "role: CHG0120144, ip: [10.56.99.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.99.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-99-253-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-99-253-0slash24"
  description  = "role: pr-c-mgt_10-99-253-0slash24, ip: [10.99.253.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.99.253.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-112-129-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-112-129-0slash24"
  description  = "role: pr-c-mgt_10-112-129-0slash24, ip: [10.112.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1appresc02-ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1appresc02-ilo"
  description  = "role: CHG0121057, ip: [10.120.130.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1appresc03-ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1appresc03-ilo"
  description  = "role: pr-c-mgt_sc1appresc03-ilo, ip: [10.120.130.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1appresc02-data" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1appresc02-data"
  description  = "role: CHG0121632, ip: [10.120.163.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1appresc03-data" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1appresc03-data"
  description  = "role: CHG0121632, ip: [10.120.163.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-112-10-0slash23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-112-10-0slash23"
  description  = "role: CHG0122059, ip: [10.112.10.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.10.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-120-130-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-120-130-0slash24"
  description  = "role: CHG0122059, ip: [10.120.130.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-120-80-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-120-80-0slash24"
  description  = "role: CHG0122059, ip: [10.120.80.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.80.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-180-130-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-180-130-0slash24"
  description  = "role: CHG0122059, ip: [10.180.130.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.130.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-180-80-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-180-80-0slash24"
  description  = "role: CHG0122059, ip: [10.180.80.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.80.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-201-254-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-201-254-0slash24"
  description  = "role: CHG0122059, ip: [10.201.254.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.254.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-210-230-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-210-230-0slash24"
  description  = "role: CHG0122059, ip: [10.210.230.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.230.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-100-254-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-100-254-0slash24"
  description  = "role: pr-c-mgt_10-100-254-0slash24, ip: [10.100.254.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.100.254.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-123-200-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-123-200-0slash24"
  description  = "role: pr-c-mgt_10-123-200-0slash24, ip: [10.123.200.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.200.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-210-8-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-210-8-0slash24"
  description  = "role: pr-c-mgt_10-210-8-0slash24, ip: [10.210.8.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.8.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-53-100-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-53-100-0slash24"
  description  = "role: pr-c-mgt_10-53-100-0slash24, ip: [10.53.100.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.100.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-54-98-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-54-98-0slash24"
  description  = "role: pr-c-mgt_10-54-98-0slash24, ip: [10.54.98.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.54.98.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-55-8-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-55-8-0slash24"
  description  = "role: pr-c-mgt_10-55-8-0slash24, ip: [10.55.8.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.8.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-8-2-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-8-2-0slash24"
  description  = "role: pr-c-mgt_10-8-2-0slash24, ip: [10.8.2.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.8.2.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-56-8-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-56-8-0slash24"
  description  = "role: pr-c-mgt_10-56-8-0slash24, ip: [10.56.8.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.8.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-201-225-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-201-225-0slash24"
  description  = "role: CHG0122059, ip: [10.201.225.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.225.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-129-10-0slash23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-129-10-0slash23"
  description  = "role: pr-c-mgt_10-129-10-0slash23, ip: [10.129.10.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.10.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsuxpremg25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsuxpremg25"
  description  = "role: pr-c-mgt_brsuxpremg25, ip: [10.210.163.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibuxpremg25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibuxpremg25"
  description  = "role: pr-c-mgt_gibuxpremg25, ip: [10.180.163.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6uxpremg01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6uxpremg01"
  description  = "role: pr-c-mgt_ld6uxpremg01, ip: [10.112.11.254]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.11.254"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremg26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremg26"
  description  = "role: pr-c-mgt_sc1uxpremg26, ip: [10.120.163.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprcmg01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprcmg01-prod-williamhill-plc"
  description  = "role: CHG0070755, ip: [10.120.141.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprcmg02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprcmg02-prod-williamhill-plc"
  description  = "role: CHG0070755, ip: [10.120.141.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-0-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-0-0s22"
  description  = "role: CHG0123933, ip: [10.125.0.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-16-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-16-0s22"
  description  = "role: CHG0123933, ip: [10.125.16.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.16.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-120-141-41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-120-141-41"
  description  = "role: pr-c-mgt_10-120-141-41, ip: [10.120.141.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-120-141-42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-120-141-42"
  description  = "role: pr-c-mgt_10-120-141-42, ip: [10.120.141.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-120-141-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-120-141-43"
  description  = "role: pr-c-mgt_10-120-141-43, ip: [10.120.141.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-120-141-44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-120-141-44"
  description  = "role: pr-c-mgt_10-120-141-44, ip: [10.120.141.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_mscuxpremn001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_mscuxpremn001"
  description  = "role: pr-c-mgt_mscuxpremn001, ip: [10.129.12.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.12.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_mscuxpremn002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_mscuxpremn002"
  description  = "role: pr-c-mgt_mscuxpremn002, ip: [10.129.12.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.12.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_aws-supernet-eu" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_aws-supernet-eu"
  description  = "role: pr-c-mgt_aws-supernet-eu, ip: [100.72.0.0/13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.0.0/13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_aws-supernet-us" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_aws-supernet-us"
  description  = "role: pr-c-mgt_aws-supernet-us, ip: [100.96.0.0/13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.96.0.0/13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_aws-supernet-us2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_aws-supernet-us2"
  description  = "role: pr-c-mgt_aws-supernet-us2, ip: [100.104.0.0/13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.104.0.0/13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1bigiq04-mgmt-prod-williamhill" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1bigiq04-mgmt-prod-williamhill"
  description  = "role: pr-c-mgt_sc1bigiq04-mgmt-prod-williamhill, ip: [10.120.140.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wfprein003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wfprein003"
  description  = "role: pr-c-mgt_sc1wfprein003, ip: [10.120.140.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wfprein004" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wfprein004"
  description  = "role: pr-c-mgt_sc1wfprein004, ip: [10.120.140.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wfprein005" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wfprein005"
  description  = "role: pr-c-mgt_sc1wfprein005, ip: [10.120.140.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-f5-1-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-f5-1-mgmt"
  description  = "role: pr-c-mgt_scc-f5-1-mgmt, ip: [10.120.140.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-f5-2-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-f5-2-mgmt"
  description  = "role: pr-c-mgt_scc-f5-2-mgmt, ip: [10.120.140.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_irewnprdc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_irewnprdc01"
  description  = "role: CHG0140344, ip: [100.72.225.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.225.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_irewnprdc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_irewnprdc02"
  description  = "role: CHG0140344, ip: [100.72.225.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.225.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_nvawnprdc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_nvawnprdc01"
  description  = "role: CHG0140344, ip: [100.97.1.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.97.1.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_nvawnprdc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_nvawnprdc02"
  description  = "role: CHG0140344, ip: [100.97.1.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.97.1.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_aws-ddos-np1-100-78-48-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_aws-ddos-np1-100-78-48-0s24"
  description  = "role: pr-c-mgt_aws-ddos-np1-100-78-48-0s24, ip: [100.78.48.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.78.48.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_aws-ddos-np1-100-78-49-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_aws-ddos-np1-100-78-49-0s24"
  description  = "role: pr-c-mgt_aws-ddos-np1-100-78-49-0s24, ip: [100.78.49.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.78.49.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmc-sc1-non-whc-prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmc-sc1-non-whc-prod"
  description  = "role: CHG0144147, ip: [10.126.236.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.236.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmc-sc1-oracle-prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmc-sc1-oracle-prod"
  description  = "role: CHG0144147, ip: [10.126.252.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.252.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmc-sc1-whc-prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmc-sc1-whc-prod"
  description  = "role: CHG0144126, ip: [10.126.204.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.204.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmc-whc-dev" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmc-whc-dev"
  description  = "role: CHG0143326, ip: [10.126.76.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.76.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmc-whc-pp-10-126-188-0_22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmc-whc-pp-10-126-188-0_22"
  description  = "role: pr-c-mgt_vmc-whc-pp-10-126-188-0_22, ip: [10.126.188.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.188.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-xiv-array-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-xiv-array-1"
  description  = "role: pr-c-mgt_brs-xiv-array-1, ip: [10.210.139.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.139.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-xiv-array-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-xiv-array-2"
  description  = "role: pr-c-mgt_brs-xiv-array-2, ip: [10.210.139.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.139.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-xiv_array-3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-xiv_array-3"
  description  = "role: pr-c-mgt_brs-xiv_array-3, ip: [10.210.139.231]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.139.231"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-xiv-array-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-xiv-array-1"
  description  = "role: pr-c-mgt_scc-xiv-array-1, ip: [10.120.139.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.139.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-xiv-array-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-xiv-array-2"
  description  = "role: pr-c-mgt_scc-xiv-array-2, ip: [10.120.139.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.139.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-xiv-array-3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-xiv-array-3"
  description  = "role: pr-c-mgt_scc-xiv-array-3, ip: [10.120.139.231]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.139.231"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-0-181" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-0-181"
  description  = "role: CHG0126802, ip: [10.125.0.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-0-182" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-0-182"
  description  = "role: CHG0126802, ip: [10.125.0.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-0-198" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-0-198"
  description  = "role: CHG0126802, ip: [10.125.0.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-0-227" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-0-227"
  description  = "role: CHG0126802, ip: [10.125.0.227]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.227"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-0-246" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-0-246"
  description  = "role: CHG0126802, ip: [10.125.0.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.246"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-0-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-0-36"
  description  = "role: CHG0126802, ip: [10.125.0.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-0-56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-0-56"
  description  = "role: CHG0126802, ip: [10.125.0.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-0-6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-0-6"
  description  = "role: CHG0126802, ip: [10.125.0.6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.6"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-0-87" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-0-87"
  description  = "role: CHG0126802, ip: [10.125.0.87]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.87"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-0-106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-0-106"
  description  = "role: CHG0128017, ip: [10.125.0.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-0-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-0-27"
  description  = "role: CHG0128017, ip: [10.125.0.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-16-205" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-16-205"
  description  = "role: CHG0128017, ip: [10.125.16.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.16.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-16-216" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-16-216"
  description  = "role: CHG0128017, ip: [10.125.16.216]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.16.216"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-16-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-16-36"
  description  = "role: CHG0128017, ip: [10.125.16.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.16.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-16-90" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-16-90"
  description  = "role: CHG0128017, ip: [10.125.16.90]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.16.90"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-4-107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-4-107"
  description  = "role: CHG0128017, ip: [10.125.4.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.4.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-4-198" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-4-198"
  description  = "role: CHG0128017, ip: [10.125.4.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.4.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsapprcsc51-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsapprcsc51-prod-williamhill-plc"
  description  = "role: CHG0114418, ip: [10.210.151.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.151.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsjump-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsjump-prod-williamhill-plc"
  description  = "role: CHG0114418, ip: [10.210.151.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.151.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsapprcsc52-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsapprcsc52-prod-williamhill-plc"
  description  = "role: CHG0114418, ip: [10.210.151.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.151.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcsc50-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcsc50-prod-williamhill-plc"
  description  = "role: CHG0114418, ip: [10.120.151.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcsc51-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcsc51-prod-williamhill-plc"
  description  = "role: CHG0114418, ip: [10.120.151.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1jump-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1jump-prod-williamhill-plc"
  description  = "role: CHG0114418, ip: [10.120.151.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_can-dr-ext-cma2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_can-dr-ext-cma2"
  description  = "role: pr-c-mgt_can-dr-ext-cma2, ip: [10.180.129.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gi-mpl-fm01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gi-mpl-fm01"
  description  = "role: pr-c-mgt_gi-mpl-fm01, ip: [10.180.129.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gib-pr-ext-cma2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gib-pr-ext-cma2"
  description  = "role: pr-c-mgt_gib-pr-ext-cma2, ip: [10.180.129.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-dr-ext-cma2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-dr-ext-cma2"
  description  = "role: pr-c-mgt_brs-dr-ext-cma2, ip: [10.180.129.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-pp-ext-cma2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-pp-ext-cma2"
  description  = "role: pr-c-mgt_brs-pp-ext-cma2, ip: [10.180.129.63]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.63"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-pr-ext-cma2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-pr-ext-cma2"
  description  = "role: pr-c-mgt_scc-pr-ext-cma2, ip: [10.180.129.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-cp-ext-cma2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-cp-ext-cma2"
  description  = "role: pr-c-mgt_stj-cp-ext-cma2, ip: [10.180.129.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_can-dr-ext-cma1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_can-dr-ext-cma1"
  description  = "role: pr-c-mgt_can-dr-ext-cma1, ip: [10.120.129.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gib-pr-ext-cma1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gib-pr-ext-cma1"
  description  = "role: pr-c-mgt_gib-pr-ext-cma1, ip: [10.120.129.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-scc-fm01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-scc-fm01"
  description  = "role: pr-c-mgt_uk-scc-fm01, ip: [10.120.129.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-dr-ext-cma1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-dr-ext-cma1"
  description  = "role: pr-c-mgt_brs-dr-ext-cma1, ip: [10.120.129.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-pp-ext-cma1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-pp-ext-cma1"
  description  = "role: pr-c-mgt_brs-pp-ext-cma1, ip: [10.120.129.63]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.63"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-pr-ext-cma1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-pr-ext-cma1"
  description  = "role: pr-c-mgt_scc-pr-ext-cma1, ip: [10.120.129.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-cp-ext-cma1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-cp-ext-cma1"
  description  = "role: pr-c-mgt_stj-cp-ext-cma1, ip: [10.120.129.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_all_networks" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_all_networks"
  description  = "role: pr-c-mgt_all_networks, ip: [10.120.80.0/24, 10.120.128.0/24, 10.120.130.0/24, 10.120.131.0/24, 10.120.132.0/24, 10.120.133.0/24, 10.120.134.0/24, 10.120.135.0/25, 10.120.136.0/24, 10.120.137.0/24, 10.120.139.224/27, 10.120.140.0/24, 10.120.143.64/27, 10.120.143.96/27, 10.120.143.160/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.80.0/24", "10.120.128.0/24", "10.120.130.0/24", "10.120.131.0/24", "10.120.132.0/24", "10.120.133.0/24", "10.120.134.0/24", "10.120.135.0/25", "10.120.136.0/24", "10.120.137.0/24", "10.120.139.224/27", "10.120.140.0/24", "10.120.143.64/27", "10.120.143.96/27", "10.120.143.160/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_web-mgmt-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_web-mgmt-network-24"
  description  = "role: pr-c-mgt_web-mgmt-network-24, ip: [10.120.131.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sccuxstnmg01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sccuxstnmg01"
  description  = "role: pr-c-mgt_sccuxstnmg01, ip: [10.120.163.130]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.130"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprnap70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprnap70"
  description  = "role: pr-c-mgt_sc1uxprnap70, ip: [10.120.146.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpromn012" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpromn012"
  description  = "role: pr-c-mgt_sc1uxpromn012, ip: [10.120.163.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcwb41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcwb41"
  description  = "role: pr-c-mgt_sc1uxprcwb41, ip: [10.120.131.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-nas-ip-range" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-nas-ip-range"
  description  = "role: SCC NAS IP range, ip: [10.120.46.40, 10.120.46.41, 10.120.46.42, 10.120.46.43, 10.120.46.44, 10.120.46.45, 10.120.46.46, 10.120.46.47, 10.120.46.48, 10.120.46.49, 10.120.46.50, 10.120.46.51, 10.120.46.52, 10.120.46.53, 10.120.46.54, 10.120.46.55, 10.120.46.56, 10.120.46.57, 10.120.46.58, 10.120.46.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.40", "10.120.46.41", "10.120.46.42", "10.120.46.43", "10.120.46.44", "10.120.46.45", "10.120.46.46", "10.120.46.47", "10.120.46.48", "10.120.46.49", "10.120.46.50", "10.120.46.51", "10.120.46.52", "10.120.46.53", "10.120.46.54", "10.120.46.55", "10.120.46.56", "10.120.46.57", "10.120.46.58", "10.120.46.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_app-mgt-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_app-mgt-network-24"
  description  = "role: pr-c-mgt_app-mgt-network-24, ip: [10.120.132.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcap45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcap45"
  description  = "role: pr-c-mgt_sc1uxprcap45, ip: [10.120.132.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcap46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcap46"
  description  = "role: pr-c-mgt_sc1uxprcap46, ip: [10.120.132.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_cde-backoffice-mgt-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_cde-backoffice-mgt-network-24"
  description  = "role: pr-c-mgt_cde-backoffice-mgt-network-24, ip: [10.120.137.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.137.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpredc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpredc03"
  description  = "role: pr-c-mgt_sc1wnpredc03, ip: [10.120.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1bigiq01-mgmt-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1bigiq01-mgmt-prod-williamhill-plc"
  description  = "role: pr-c-mgt_sc1bigiq01-mgmt-prod-williamhill-plc, ip: [10.120.140.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1bigiq03-mgmt-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1bigiq03-mgmt-prod-williamhill-plc"
  description  = "role: pr-c-mgt_sc1bigiq03-mgmt-prod-williamhill-plc, ip: [10.120.140.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-vpn-pool"
  description  = "role: pr-c-mgt_brs-vpn-pool, ip: [192.168.2.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1prappsc02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1prappsc02-prod-williamhill-plc"
  description  = "role: pr-c-mgt_sc1prappsc02-prod-williamhill-plc, ip: [10.120.134.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-sc1-network-mgmt-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-sc1-network-mgmt-24"
  description  = "role: CHG0017289, ip: [10.120.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_bladelogic-dmz-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_bladelogic-dmz-network-24"
  description  = "role: pr-c-mgt_bladelogic-dmz-network-24, ip: [10.120.136.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_net-10-120-140-0_24-sccstringray" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_net-10-120-140-0_24-sccstringray"
  description  = "role: pr-c-mgt_net-10-120-140-0_24-sccstringray, ip: [10.120.140.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmhost-mgt-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmhost-mgt-network-24"
  description  = "role: pr-c-mgt_vmhost-mgt-network-24, ip: [10.120.134.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_us-esxi-hosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_us-esxi-hosts"
  description  = "role: CHG0141104, ip: [10.174.0.0/15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.174.0.0/15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1prapvc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1prapvc01"
  description  = "role: pr-c-mgt_sc1prapvc01, ip: [10.120.134.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.253"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremg30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremg30"
  description  = "role: pr-c-mgt_sc1uxpremg30, ip: [10.120.136.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_copxbld16api001-co1-cop-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_copxbld16api001-co1-cop-williamhill-plc"
  description  = "role: CHG0140599, ip: [10.178.145.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.178.145.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-internal-asa" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-internal-asa"
  description  = "role: pr-c-mgt_scc-internal-asa, ip: [10.120.129.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_pr-cde-front-cx-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_pr-cde-front-cx-mgmt"
  description  = "role: CHG0068990, ip: [10.121.10.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn79" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn79"
  description  = "role: SCC Splunk Heavy Forwarder, ip: [10.120.163.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-scc-wsus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-scc-wsus"
  description  = "role: pr-c-mgt_uk-scc-wsus, ip: [10.120.163.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6wnprwsus01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6wnprwsus01"
  description  = "role: pr-c-mgt_ld6wnprwsus01, ip: [10.112.13.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.13.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brswnprwsus01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brswnprwsus01"
  description  = "role: pr-c-mgt_brswnprwsus01, ip: [10.210.163.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_rsa-scc-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_rsa-scc-new"
  description  = "role: pr-c-mgt_rsa-scc-new, ip: [10.120.129.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibux950-02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibux950-02"
  description  = "role: pr-c-mgt_gibux950-02, ip: [10.180.163.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.50"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-solarwinds" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-solarwinds"
  description  = "role: CHG0035636, ip: [10.120.163.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-sc1-netbrain01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-sc1-netbrain01"
  description  = "role: CHG0056829, ip: [10.120.163.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-cacti" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-cacti"
  description  = "role: CHG0015230, ip: [10.120.163.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-ncs1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-ncs1"
  description  = "role: pr-c-mgt_sc1-ncs1, ip: [10.120.136.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-wn-pre-mg01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-wn-pre-mg01"
  description  = "role: CHG0015826, ip: [10.120.136.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsuxprein02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsuxprein02"
  description  = "role: CHG0030409, ip: [10.210.163.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprein12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprein12"
  description  = "role: pr-c-mgt_sc1uxprein12, ip: [10.120.163.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprenw01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprenw01"
  description  = "role: pr-c-mgt_sc1uxprenw01, ip: [10.120.129.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-tpam" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-tpam"
  description  = "role: pr-c-mgt_scc-tpam, ip: [10.120.136.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-tpam" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-tpam"
  description  = "role: pr-c-mgt_brs-tpam, ip: [192.168.10.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.10.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gib-c-web-mg-net" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gib-c-web-mg-net"
  description  = "role: pr-c-mgt_gib-c-web-mg-net, ip: [10.180.131.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.131.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sccappresc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sccappresc01"
  description  = "role: CHG0033315, ip: [10.120.163.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibwnprcmg003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibwnprcmg003"
  description  = "role: pr-c-mgt_gibwnprcmg003, ip: [10.180.142.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.142.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprein001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprein001"
  description  = "role: pr-c-mgt_sc1uxprein001, ip: [10.120.163.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibux9002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibux9002"
  description  = "role: pr-c-mgt_gibux9002, ip: [10.180.163.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremg001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremg001"
  description  = "role: pr-c-mgt_sc1uxpremg001, ip: [10.120.163.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsuxpremg001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsuxpremg001"
  description  = "role: pr-c-mgt_brsuxpremg001, ip: [10.210.163.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1prapvro01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1prapvro01"
  description  = "role: CHG0092547, ip: [10.120.134.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.250"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsdatafabman01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsdatafabman01"
  description  = "role: pr-c-mgt_brsdatafabman01, ip: [10.210.163.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.246"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1dcnm01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1dcnm01"
  description  = "role: pr-c-mgt_sc1dcnm01, ip: [10.120.143.176]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.176"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn74"
  description  = "role: CHG0067511, ip: [10.120.163.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpremg44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpremg44"
  description  = "role: pr-c-mgt_sc1wnpremg44, ip: [10.120.163.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_nj2-whc-build-server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_nj2-whc-build-server"
  description  = "role: pr-c-mgt_nj2-whc-build-server, ip: [10.178.97.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.178.97.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_inpxbld16api001-in1-inp-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_inpxbld16api001-in1-inp-williamhill-plc"
  description  = "role: pr-c-mgt_inpxbld16api001-in1-inp-williamhill-plc, ip: [10.178.129.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.178.129.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpresc002-mgmt-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpresc002-mgmt-prod-williamhill-plc"
  description  = "role: pr-c-mgt_sc1uxpresc002-mgmt-prod-williamhill-plc, ip: [10.120.143.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.69"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxcpemn001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxcpemn001"
  description  = "role: Monitoring Server using scripts to collect data, ip: [10.120.195.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.195.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-enc02-ilo4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-enc02-ilo4"
  description  = "role: pr-c-mgt_sc1-enc02-ilo4, ip: [10.120.130.109]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.109"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-enc04-ilo9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-enc04-ilo9"
  description  = "role: pr-c-mgt_sc1-enc04-ilo9, ip: [10.120.130.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcmg001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcmg001"
  description  = "role: pr-c-mgt_sc1apprcmg001, ip: [10.120.136.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcmg01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcmg01"
  description  = "role: pr-c-mgt_sc1uxprcmg01, ip: [10.120.136.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sccstorageprocesserb" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sccstorageprocesserb"
  description  = "role: pr-c-mgt_sccstorageprocesserb, ip: [10.120.143.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_us-10-178-0-0s15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_us-10-178-0-0s15"
  description  = "role: pr-c-mgt_us-10-178-0-0s15, ip: [10.178.0.0/15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.178.0.0/15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_net-10-120-129-0_24-scc-networkmanagement" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_net-10-120-129-0_24-scc-networkmanagement"
  description  = "role: CHG0056783, ip: [10.120.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn81"
  description  = "role: pr-c-mgt_sc1uxpremn81, ip: [10.120.163.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibux998" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibux998"
  description  = "role: pr-c-mgt_gibux998, ip: [10.180.163.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn17"
  description  = "role: pr-c-mgt_sc1uxpremn17, ip: [10.120.163.75]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.75"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmcprapvro01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmcprapvro01-prod-williamhill-plc"
  description  = "role: pr-c-mgt_vmcprapvro01-prod-williamhill-plc, ip: [10.156.3.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.3.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibwnprndcnm01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibwnprndcnm01"
  description  = "role: pr-c-mgt_gibwnprndcnm01, ip: [10.180.143.176]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.143.176"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-4-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-4-0s22"
  description  = "role: pr-c-mgt_10-125-4-0s22, ip: [10.125.4.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.4.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-0-0-0_8_range" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-0-0-0_8_range"
  description  = "role: pr-c-mgt_10-0-0-0_8_range, ip: [10.0.0.0/8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.0.0.0/8"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb017" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb017"
  description  = "role: pr-c-mgt_sc1apprcwb017, ip: [10.120.131.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb018" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb018"
  description  = "role: pr-c-mgt_sc1apprcwb018, ip: [10.120.131.209]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.209"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb019" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb019"
  description  = "role: pr-c-mgt_sc1apprcwb019, ip: [10.120.131.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb020" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb020"
  description  = "role: pr-c-mgt_sc1apprcwb020, ip: [10.120.131.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb021" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb021"
  description  = "role: pr-c-mgt_sc1apprcwb021, ip: [10.120.131.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb022" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb022"
  description  = "role: pr-c-mgt_sc1apprcwb022, ip: [10.120.131.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb023" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb023"
  description  = "role: pr-c-mgt_sc1apprcwb023, ip: [10.120.131.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb024" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb024"
  description  = "role: pr-c-mgt_sc1apprcwb024, ip: [10.120.131.215]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.215"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb013" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb013"
  description  = "role: pr-c-mgt_sc1apprcwb013, ip: [10.120.131.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb014" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb014"
  description  = "role: pr-c-mgt_sc1apprcwb014, ip: [10.120.131.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb015" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb015"
  description  = "role: pr-c-mgt_sc1apprcwb015, ip: [10.120.131.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb016" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb016"
  description  = "role: pr-c-mgt_sc1apprcwb016, ip: [10.120.131.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.207"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-ux-pre-mn13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-ux-pre-mn13"
  description  = "role: CHG0018071, ip: [10.120.163.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb005" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb005"
  description  = "role: pr-c-mgt_sc1apprcwb005, ip: [10.120.131.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.246"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb006" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb006"
  description  = "role: pr-c-mgt_sc1apprcwb006, ip: [10.120.131.247]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.247"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb007" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb007"
  description  = "role: pr-c-mgt_sc1apprcwb007, ip: [10.120.131.248]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.248"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb008" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb008"
  description  = "role: pr-c-mgt_sc1apprcwb008, ip: [10.120.131.249]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.249"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb11"
  description  = "role: pr-c-mgt_sc1apprcwb11, ip: [10.120.131.191]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.191"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcap31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcap31"
  description  = "role: pr-c-mgt_sc1uxprcap31, ip: [10.120.132.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcap32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcap32"
  description  = "role: pr-c-mgt_sc1uxprcap32, ip: [10.120.132.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcwb42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcwb42"
  description  = "role: pr-c-mgt_sc1uxprcwb42, ip: [10.120.131.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb03"
  description  = "role: pr-c-mgt_sc1apprcwb03, ip: [10.120.131.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb04"
  description  = "role: pr-c-mgt_sc1apprcwb04, ip: [10.120.131.184]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.184"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-nms-win" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-nms-win"
  description  = "role: pr-c-mgt_brs-nms-win, ip: [10.210.163.247]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.247"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn001"
  description  = "role: pr-c-mgt_sc1uxpremn001, ip: [10.120.163.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn77" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn77"
  description  = "role: pr-c-mgt_sc1uxpremn77, ip: [10.120.163.77]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.77"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_prdxclp25fwd001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_prdxclp25fwd001"
  description  = "role: pr-c-mgt_prdxclp25fwd001, ip: [10.121.10.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_prdxclp25fwd002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_prdxclp25fwd002"
  description  = "role: pr-c-mgt_prdxclp25fwd002, ip: [10.121.10.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_aws-us-ddos-big-ip-net" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_aws-us-ddos-big-ip-net"
  description  = "role: pr-c-mgt_aws-us-ddos-big-ip-net, ip: [10.125.16.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.16.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_aws-irl-ddos-big-ip-net" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_aws-irl-ddos-big-ip-net"
  description  = "role: pr-c-mgt_aws-irl-ddos-big-ip-net, ip: [10.125.4.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.4.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_aws-ddos-orp-ext" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_aws-ddos-orp-ext"
  description  = "role: pr-c-mgt_aws-ddos-orp-ext, ip: [10.125.24.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.24.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_aws-ddos-np1-100-78-50-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_aws-ddos-np1-100-78-50-0s24"
  description  = "role: pr-c-mgt_aws-ddos-np1-100-78-50-0s24, ip: [100.78.50.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.78.50.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_aws-ddos-pt1-bigip-net" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_aws-ddos-pt1-bigip-net"
  description  = "role: pr-c-mgt_aws-ddos-pt1-bigip-net, ip: [10.125.8.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.8.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-125-20-0slash22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-125-20-0slash22"
  description  = "role: CHG0125909, ip: [10.125.20.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.20.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_svr-sc1wnprrto01-mgmt-re" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_svr-sc1wnprrto01-mgmt-re"
  description  = "role: pr-c-mgt_svr-sc1wnprrto01-mgmt-re, ip: [10.120.180.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_svr-sc1wnprrto02-mgmt-re" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_svr-sc1wnprrto02-mgmt-re"
  description  = "role: pr-c-mgt_svr-sc1wnprrto02-mgmt-re, ip: [10.120.180.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_serveroperations-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_serveroperations-27"
  description  = "role: pr-c-mgt_serveroperations-27, ip: [10.1.82.160/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.160/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsuxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsuxprbkms01"
  description  = "role: CHG0140759, ip: [10.210.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsuxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsuxprbkms02"
  description  = "role: CHG0140759, ip: [10.210.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsuxprbkms03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsuxprbkms03"
  description  = "role: CHG0140759, ip: [10.210.46.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_192-168-3-208slash28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_192-168-3-208slash28"
  description  = "role: CHG0123928, ip: [192.168.3.208/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.208/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_192-168-3-2slash27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_192-168-3-2slash27"
  description  = "role: CHG0123928, ip: [192.168.3.224/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.3.224/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremg005-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremg005-prod-williamhill-plc"
  description  = "role: pr-c-mgt_sc1uxpremg005-prod-williamhill-plc, ip: [10.120.163.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-sc1-cr01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-sc1-cr01"
  description  = "role: pr-c-mgt_uk-sc1-cr01, ip: [10.120.129.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-sc1-cr02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-sc1-cr02"
  description  = "role: pr-c-mgt_uk-sc1-cr02, ip: [10.120.129.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_server-ilo-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_server-ilo-network-24"
  description  = "role: pr-c-mgt_server-ilo-network-24, ip: [10.120.130.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpremg10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpremg10"
  description  = "role: CHG0018071, ip: [10.120.136.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpremg11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpremg11"
  description  = "role: CHG0018071, ip: [10.120.136.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpremn20a" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpremn20a"
  description  = "role: pr-c-mgt_sc1wnpremn20a, ip: [10.120.163.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpremn21a" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpremn21a"
  description  = "role: pr-c-mgt_sc1wnpremn21a, ip: [10.120.163.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprevc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprevc01"
  description  = "role: pr-c-mgt_sc1wnprevc01, ip: [10.120.134.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-nms-man" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-nms-man"
  description  = "role: pr-c-mgt_scc-nms-man, ip: [10.120.163.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stjwnats" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stjwnats"
  description  = "role: CHG0015319, ip: [10.50.3.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.50.3.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gib-storage-subnet" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gib-storage-subnet"
  description  = "role: pr-c-mgt_gib-storage-subnet, ip: [10.180.143.160/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.143.160/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6-san-switches" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6-san-switches"
  description  = "role: CHG0118320, range: [10.112.11.0-10.112.11.254]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.11.0", "10.112.11.1", "10.112.11.2", "10.112.11.3", "10.112.11.4", "10.112.11.5", "10.112.11.6", "10.112.11.7", "10.112.11.8", "10.112.11.9", "10.112.11.10", "10.112.11.11", "10.112.11.12", "10.112.11.13", "10.112.11.14", "10.112.11.15", "10.112.11.16", "10.112.11.17", "10.112.11.18", "10.112.11.19", "10.112.11.20", "10.112.11.21", "10.112.11.22", "10.112.11.23", "10.112.11.24", "10.112.11.25", "10.112.11.26", "10.112.11.27", "10.112.11.28", "10.112.11.29", "10.112.11.30", "10.112.11.31", "10.112.11.32", "10.112.11.33", "10.112.11.34", "10.112.11.35", "10.112.11.36", "10.112.11.37", "10.112.11.38", "10.112.11.39", "10.112.11.40", "10.112.11.41", "10.112.11.42", "10.112.11.43", "10.112.11.44", "10.112.11.45", "10.112.11.46", "10.112.11.47", "10.112.11.48", "10.112.11.49", "10.112.11.50", "10.112.11.51", "10.112.11.52", "10.112.11.53", "10.112.11.54", "10.112.11.55", "10.112.11.56", "10.112.11.57", "10.112.11.58", "10.112.11.59", "10.112.11.60", "10.112.11.61", "10.112.11.62", "10.112.11.63", "10.112.11.64", "10.112.11.65", "10.112.11.66", "10.112.11.67", "10.112.11.68", "10.112.11.69", "10.112.11.70", "10.112.11.71", "10.112.11.72", "10.112.11.73", "10.112.11.74", "10.112.11.75", "10.112.11.76", "10.112.11.77", "10.112.11.78", "10.112.11.79", "10.112.11.80", "10.112.11.81", "10.112.11.82", "10.112.11.83", "10.112.11.84", "10.112.11.85", "10.112.11.86", "10.112.11.87", "10.112.11.88", "10.112.11.89", "10.112.11.90", "10.112.11.91", "10.112.11.92", "10.112.11.93", "10.112.11.94", "10.112.11.95", "10.112.11.96", "10.112.11.97", "10.112.11.98", "10.112.11.99", "10.112.11.100", "10.112.11.101", "10.112.11.102", "10.112.11.103", "10.112.11.104", "10.112.11.105", "10.112.11.106", "10.112.11.107", "10.112.11.108", "10.112.11.109", "10.112.11.110", "10.112.11.111", "10.112.11.112", "10.112.11.113", "10.112.11.114", "10.112.11.115", "10.112.11.116", "10.112.11.117", "10.112.11.118", "10.112.11.119", "10.112.11.120", "10.112.11.121", "10.112.11.122", "10.112.11.123", "10.112.11.124", "10.112.11.125", "10.112.11.126", "10.112.11.127", "10.112.11.128", "10.112.11.129", "10.112.11.130", "10.112.11.131", "10.112.11.132", "10.112.11.133", "10.112.11.134", "10.112.11.135", "10.112.11.136", "10.112.11.137", "10.112.11.138", "10.112.11.139", "10.112.11.140", "10.112.11.141", "10.112.11.142", "10.112.11.143", "10.112.11.144", "10.112.11.145", "10.112.11.146", "10.112.11.147", "10.112.11.148", "10.112.11.149", "10.112.11.150", "10.112.11.151", "10.112.11.152", "10.112.11.153", "10.112.11.154", "10.112.11.155", "10.112.11.156", "10.112.11.157", "10.112.11.158", "10.112.11.159", "10.112.11.160", "10.112.11.161", "10.112.11.162", "10.112.11.163", "10.112.11.164", "10.112.11.165", "10.112.11.166", "10.112.11.167", "10.112.11.168", "10.112.11.169", "10.112.11.170", "10.112.11.171", "10.112.11.172", "10.112.11.173", "10.112.11.174", "10.112.11.175", "10.112.11.176", "10.112.11.177", "10.112.11.178", "10.112.11.179", "10.112.11.180", "10.112.11.181", "10.112.11.182", "10.112.11.183", "10.112.11.184", "10.112.11.185", "10.112.11.186", "10.112.11.187", "10.112.11.188", "10.112.11.189", "10.112.11.190", "10.112.11.191", "10.112.11.192", "10.112.11.193", "10.112.11.194", "10.112.11.195", "10.112.11.196", "10.112.11.197", "10.112.11.198", "10.112.11.199", "10.112.11.200", "10.112.11.201", "10.112.11.202", "10.112.11.203", "10.112.11.204", "10.112.11.205", "10.112.11.206", "10.112.11.207", "10.112.11.208", "10.112.11.209", "10.112.11.210", "10.112.11.211", "10.112.11.212", "10.112.11.213", "10.112.11.214", "10.112.11.215", "10.112.11.216", "10.112.11.217", "10.112.11.218", "10.112.11.219", "10.112.11.220", "10.112.11.221", "10.112.11.222", "10.112.11.223", "10.112.11.224", "10.112.11.225", "10.112.11.226", "10.112.11.227", "10.112.11.228", "10.112.11.229", "10.112.11.230", "10.112.11.231", "10.112.11.232", "10.112.11.233", "10.112.11.234", "10.112.11.235", "10.112.11.236", "10.112.11.237", "10.112.11.238", "10.112.11.239", "10.112.11.240", "10.112.11.241", "10.112.11.242", "10.112.11.243", "10.112.11.244", "10.112.11.245", "10.112.11.246", "10.112.11.247", "10.112.11.248", "10.112.11.249", "10.112.11.250", "10.112.11.251", "10.112.11.252", "10.112.11.253", "10.112.11.254"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpremn01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpremn01"
  description  = "role: pr-c-mgt_sc1wnpremn01, ip: [10.120.163.76]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.76"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibux181" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibux181"
  description  = "role: pr-c-mgt_gibux181, ip: [10.180.131.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.131.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibux191" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibux191"
  description  = "role: pr-c-mgt_gibux191, ip: [10.180.131.191]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.131.191"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_netsec-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_netsec-27"
  description  = "role: pr-c-mgt_netsec-27, ip: [10.1.82.64/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.64/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_infosec-28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_infosec-28"
  description  = "role: CHG0024220, ip: [10.1.82.48/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.48/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_netsec-oncall-28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_netsec-oncall-28"
  description  = "role: pr-c-mgt_netsec-oncall-28, ip: [172.16.41.208/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.16.41.208/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-stuarthenshaw" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-stuarthenshaw"
  description  = "role: pr-c-mgt_lcw-stuarthenshaw, ip: [10.1.83.222]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.222"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-craigtate" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-craigtate"
  description  = "role: pr-c-mgt_lcw-craigtate, ip: [10.1.82.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-fwab-mgmt-nat" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-fwab-mgmt-nat"
  description  = "role: pr-c-mgt_brs-fwab-mgmt-nat, ip: [10.210.129.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_net_10-55-60-0_28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_net_10-55-60-0_28"
  description  = "role: pr-c-mgt_net_10-55-60-0_28, ip: [10.55.60.0/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.60.0/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-180-19-180" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-180-19-180"
  description  = "role: pr-c-mgt_host-10-180-19-180, ip: [10.180.19.180]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.180"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gib-alejandrogalindo2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gib-alejandrogalindo2"
  description  = "role: pr-c-mgt_gib-alejandrogalindo2, ip: [10.180.20.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-180-18-126" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-180-18-126"
  description  = "role: pr-c-mgt_host-10-180-18-126, ip: [10.180.18.126]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.126"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_net-10-17-100-0-slash25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_net-10-17-100-0-slash25"
  description  = "role: pr-c-mgt_net-10-17-100-0-slash25, ip: [10.17.100.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-180-19-248" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-180-19-248"
  description  = "role: pr-c-mgt_host-10-180-19-248, ip: [10.180.19.248]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.248"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-karolstatkiewicz" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-karolstatkiewicz"
  description  = "role: pr-c-mgt_who-karolstatkiewicz, ip: [10.180.19.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gib-alejandrogalindo1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gib-alejandrogalindo1"
  description  = "role: pr-c-mgt_gib-alejandrogalindo1, ip: [10.180.19.180]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.180"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-180-18-76" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-180-18-76"
  description  = "role: pr-c-mgt_host-10-180-18-76, ip: [10.180.18.76]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.76"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-180-19-97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-180-19-97"
  description  = "role: pr-c-mgt_host-10-180-19-97, ip: [10.180.19.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-180-20-189" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-180-20-189"
  description  = "role: pr-c-mgt_host-10-180-20-189, ip: [10.180.20.189]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.189"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-1-86-37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-1-86-37"
  description  = "role: pr-c-mgt_host-10-1-86-37, ip: [10.1.86.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-1-87-34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-1-87-34"
  description  = "role: pr-c-mgt_host-10-1-87-34, ip: [10.1.87.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.87.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-1-29-37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-1-29-37"
  description  = "role: pr-c-mgt_host-10-1-29-37, ip: [10.1.29.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-17-8-37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-17-8-37"
  description  = "role: pr-c-mgt_host-10-17-8-37, ip: [10.17.8.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-180-19-205" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-180-19-205"
  description  = "role: pr-c-mgt_host-10-180-19-205, ip: [10.180.19.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-180-18-100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-180-18-100"
  description  = "role: pr-c-mgt_host-10-180-18-100, ip: [10.180.18.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_host-10-180-19-145" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_host-10-180-19-145"
  description  = "role: pr-c-mgt_host-10-180-19-145, ip: [10.180.19.145]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.145"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-neilbellamy" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-neilbellamy"
  description  = "role: pr-c-mgt_who-neilbellamy, ip: [10.180.19.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-1-78-37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-1-78-37"
  description  = "role: pr-c-mgt_10-1-78-37, ip: [10.1.78.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gib-catalinmerluscalap" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gib-catalinmerluscalap"
  description  = "role: pr-c-mgt_gib-catalinmerluscalap, ip: [10.180.18.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gib-carlospimentel" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gib-carlospimentel"
  description  = "role: pr-c-mgt_gib-carlospimentel, ip: [10.180.18.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-neil-bellamy" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-neil-bellamy"
  description  = "role: pr-c-mgt_who-neil-bellamy, ip: [10.180.19.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-vincebaker" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-vincebaker"
  description  = "role: pr-c-mgt_lcw-vincebaker, ip: [10.1.83.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcmg01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcmg01"
  description  = "role: pr-c-mgt_sc1apprcmg01, ip: [10.120.136.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibux182" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibux182"
  description  = "role: pr-c-mgt_gibux182, ip: [10.180.131.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.131.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb01"
  description  = "role: pr-c-mgt_sc1apprcwb01, ip: [10.120.131.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1apprcwb02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1apprcwb02"
  description  = "role: pr-c-mgt_sc1apprcwb02, ip: [10.120.131.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_citywalk-23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_citywalk-23"
  description  = "role: pr-c-mgt_citywalk-23, ip: [10.1.82.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-ncs2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-ncs2"
  description  = "role: pr-c-mgt_sc1-ncs2, ip: [10.120.136.141]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.141"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_service_desk_team" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_service_desk_team"
  description  = "role: CHG0015230, ip: [10.1.83.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.0/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-trading-ia-range" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-trading-ia-range"
  description  = "role: pr-c-mgt_stj-trading-ia-range, ip: [10.1.112.240/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.240/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lsj-monitoringpc2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lsj-monitoringpc2"
  description  = "role: pr-c-mgt_lsj-monitoringpc2, ip: [10.1.112.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-grahameades" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-grahameades"
  description  = "role: CHG0056597, ip: [10.1.74.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_nev-bryanmarek" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_nev-bryanmarek"
  description  = "role: pr-c-mgt_nev-bryanmarek, ip: [10.18.10.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.10.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-carlosmendez" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-carlosmendez"
  description  = "role: pr-c-mgt_who-carlosmendez, ip: [10.180.18.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-dandoyle" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-dandoyle"
  description  = "role: pr-c-mgt_who-dandoyle, ip: [10.180.18.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-danesquival" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-danesquival"
  description  = "role: pr-c-mgt_who-danesquival, ip: [10.180.19.178]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.178"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-edwardlynn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-edwardlynn"
  description  = "role: pr-c-mgt_who-edwardlynn, ip: [10.180.18.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-ericheichinger" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-ericheichinger"
  description  = "role: pr-c-mgt_who-ericheichinger, ip: [10.180.19.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-gorkamolero" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-gorkamolero"
  description  = "role: pr-c-mgt_who-gorkamolero, ip: [10.180.19.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.207"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-istvanpapp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-istvanpapp"
  description  = "role: pr-c-mgt_who-istvanpapp, ip: [10.180.19.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-jamesmoody" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-jamesmoody"
  description  = "role: pr-c-mgt_who-jamesmoody, ip: [10.180.18.169]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.169"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-josetalens" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-josetalens"
  description  = "role: pr-c-mgt_who-josetalens, ip: [10.180.19.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-martinkuegler" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-martinkuegler"
  description  = "role: pr-c-mgt_who-martinkuegler, ip: [10.180.18.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-michaeldally" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-michaeldally"
  description  = "role: pr-c-mgt_who-michaeldally, ip: [10.180.19.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-michalhorzela" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-michalhorzela"
  description  = "role: pr-c-mgt_who-michalhorzela, ip: [10.180.18.157]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.157"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-patrickdiloreto" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-patrickdiloreto"
  description  = "role: pr-c-mgt_who-patrickdiloreto, ip: [10.180.18.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-pedrogutierrez" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-pedrogutierrez"
  description  = "role: pr-c-mgt_who-pedrogutierrez, ip: [10.180.18.113]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.113"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-thomasmodeneis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-thomasmodeneis"
  description  = "role: pr-c-mgt_who-thomasmodeneis, ip: [10.180.18.189]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.189"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-jennyfarrell" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-jennyfarrell"
  description  = "role: pr-c-mgt_lcw-jennyfarrell, ip: [10.1.82.157]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.157"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-robrussell" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-robrussell"
  description  = "role: pr-c-mgt_lcw-robrussell, ip: [10.1.82.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-stevehammersley" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-stevehammersley"
  description  = "role: pr-c-mgt_lcw-stevehammersley, ip: [10.1.82.141]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.141"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-steveibbotson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-steveibbotson"
  description  = "role: pr-c-mgt_lcw-steveibbotson, ip: [10.1.82.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-andrewdonachie" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-andrewdonachie"
  description  = "role: pr-c-mgt_lcw-andrewdonachie, ip: [10.1.82.216]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.216"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-chriswren" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-chriswren"
  description  = "role: pr-c-mgt_lcw-chriswren, ip: [10.1.82.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-danferry" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-danferry"
  description  = "role: pr-c-mgt_lcw-danferry, ip: [10.1.82.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-davidbarszczak" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-davidbarszczak"
  description  = "role: pr-c-mgt_lcw-davidbarszczak, ip: [10.1.82.226]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.226"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-garethsephton" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-garethsephton"
  description  = "role: pr-c-mgt_lcw-garethsephton, ip: [10.1.82.219]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.219"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-markpetrie" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-markpetrie"
  description  = "role: pr-c-mgt_lcw-markpetrie, ip: [10.1.82.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-ravisingh" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-ravisingh"
  description  = "role: pr-c-mgt_lcw-ravisingh, ip: [10.1.83.129]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.129"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-richardscott" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-richardscott"
  description  = "role: pr-c-mgt_lcw-richardscott, ip: [10.1.82.228]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.228"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-roblewis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-roblewis"
  description  = "role: pr-c-mgt_lcw-roblewis, ip: [10.1.82.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-stevewilson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-stevewilson"
  description  = "role: pr-c-mgt_lcw-stevewilson, ip: [10.1.82.227]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.227"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-tomfield" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-tomfield"
  description  = "role: pr-c-mgt_lcw-tomfield, ip: [10.1.82.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-alastairmontgomery" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-alastairmontgomery"
  description  = "role: pr-c-mgt_stj-alastairmontgomery, ip: [10.1.74.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-joncandlin" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-joncandlin"
  description  = "role: pr-c-mgt_stj-joncandlin, ip: [10.1.74.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-marcuscampbell2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-marcuscampbell2"
  description  = "role: pr-c-mgt_who-marcuscampbell2, ip: [10.180.19.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-vincentpalmer" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-vincentpalmer"
  description  = "role: pr-c-mgt_who-vincentpalmer, ip: [10.1.82.194]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.194"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-vincentpalmer2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-vincentpalmer2"
  description  = "role: pr-c-mgt_who-vincentpalmer2, ip: [10.180.18.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-marcuscampbell" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-marcuscampbell"
  description  = "role: pr-c-mgt_who-marcuscampbell, ip: [10.180.19.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_usr-wpp-agalindo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_usr-wpp-agalindo"
  description  = "role: pr-c-mgt_usr-wpp-agalindo, ip: [10.180.20.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_usr-wpp-agalindo2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_usr-wpp-agalindo2"
  description  = "role: pr-c-mgt_usr-wpp-agalindo2, ip: [10.180.20.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_usr-lcw-nchrzanowski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_usr-lcw-nchrzanowski"
  description  = "role: pr-c-mgt_usr-lcw-nchrzanowski, ip: [10.1.83.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-gaganthakur" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-gaganthakur"
  description  = "role: pr-c-mgt_lcw-gaganthakur, ip: [10.1.83.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-richardgarforth" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-richardgarforth"
  description  = "role: pr-c-mgt_lcw-richardgarforth, ip: [10.1.83.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-mikebest" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-mikebest"
  description  = "role: pr-c-mgt_stj-mikebest, ip: [10.1.74.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gib-connor" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gib-connor"
  description  = "role: pr-c-mgt_gib-connor, ip: [10.180.21.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.21.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-55-1-190" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-55-1-190"
  description  = "role: pr-c-mgt_10-55-1-190, ip: [10.55.1.190]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.1.190"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-aleksanderjarek" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-aleksanderjarek"
  description  = "role: pr-c-mgt_krk-aleksanderjarek, ip: [10.55.0.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-bartoszmarona" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-bartoszmarona"
  description  = "role: pr-c-mgt_krk-bartoszmarona, ip: [10.55.0.237]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.237"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-bartoszopila" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-bartoszopila"
  description  = "role: pr-c-mgt_krk-bartoszopila, ip: [10.55.3.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.3.120"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-jakubswider" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-jakubswider"
  description  = "role: pr-c-mgt_krk-jakubswider, ip: [10.55.0.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-kamiljasko" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-kamiljasko"
  description  = "role: pr-c-mgt_krk-kamiljasko, ip: [10.55.0.238]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.238"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-luciansilva" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-luciansilva"
  description  = "role: pr-c-mgt_krk-luciansilva, ip: [10.55.0.234]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.234"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-lukaszziemba" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-lukaszziemba"
  description  = "role: pr-c-mgt_krk-lukaszziemba, ip: [10.55.0.241]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.241"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-maciejwolk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-maciejwolk"
  description  = "role: pr-c-mgt_krk-maciejwolk, ip: [10.55.0.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-pawelskarbinski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-pawelskarbinski"
  description  = "role: pr-c-mgt_krk-pawelskarbinski, ip: [10.55.0.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-piotrkalinski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-piotrkalinski"
  description  = "role: pr-c-mgt_krk-piotrkalinski, ip: [10.55.0.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-piotrkapica" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-piotrkapica"
  description  = "role: pr-c-mgt_krk-piotrkapica, ip: [10.55.0.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.246"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-raulacedo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-raulacedo"
  description  = "role: pr-c-mgt_krk-raulacedo, ip: [10.55.0.228]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.228"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-robertscislowicz" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-robertscislowicz"
  description  = "role: pr-c-mgt_krk-robertscislowicz, ip: [10.55.1.129]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.1.129"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_desktop-c0reen2-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_desktop-c0reen2-prod-williamhill-plc"
  description  = "role: pr-c-mgt_desktop-c0reen2-prod-williamhill-plc, ip: [10.55.1.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.1.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-eoc_team" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-eoc_team"
  description  = "role: pr-c-mgt_krk-eoc_team, ip: [10.55.14.0/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.0/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-eoc_team-wifi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-eoc_team-wifi"
  description  = "role: pr-c-mgt_krk-eoc_team-wifi, ip: [10.55.226.0/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.0/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-pawel_skarbinski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-pawel_skarbinski"
  description  = "role: Pawel _Skarbinski, ip: [10.55.14.2]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.2"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-1-74-72" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-1-74-72"
  description  = "role: pr-c-mgt_10-1-74-72, ip: [10.1.74.72]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.72"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_birstall-fwa" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_birstall-fwa"
  description  = "role: CHG0039249, ip: [10.210.129.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_birstall-fwb" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_birstall-fwb"
  description  = "role: CHG0039249, ip: [10.210.129.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-test-global-fw01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-test-global-fw01"
  description  = "role: pr-c-mgt_brs-test-global-fw01, ip: [10.210.129.177]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.177"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_birstall-fwb-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_birstall-fwb-new"
  description  = "role: pr-c-mgt_birstall-fwb-new, ip: [10.210.129.178]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.178"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-test-global-cma1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-test-global-cma1"
  description  = "role: pr-c-mgt_brs-test-global-cma1, ip: [10.120.129.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-lab-ext-cma1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-lab-ext-cma1"
  description  = "role: pr-c-mgt_brs-lab-ext-cma1, ip: [10.120.129.76]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.76"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-lab-ext-cma2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-lab-ext-cma2"
  description  = "role: pr-c-mgt_brs-lab-ext-cma2, ip: [10.120.129.77]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.77"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-210-129-241" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-210-129-241"
  description  = "role: pr-c-mgt_10-210-129-241, ip: [10.210.129.241]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.241"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-210-129-242" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-210-129-242"
  description  = "role: pr-c-mgt_10-210-129-242, ip: [10.210.129.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-210-129-243" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-210-129-243"
  description  = "role: pr-c-mgt_10-210-129-243, ip: [10.210.129.243]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.243"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-sc1-fw01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-sc1-fw01"
  description  = "role: pr-c-mgt_uk-sc1-fw01, ip: [10.120.129.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-sc1-fw02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-sc1-fw02"
  description  = "role: pr-c-mgt_uk-sc1-fw02, ip: [10.120.129.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_orbis-dr-nat" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_orbis-dr-nat"
  description  = "role: INC0442038, ip: [10.194.30.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.194.30.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krakow-nat-hide" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krakow-nat-hide"
  description  = "role: pr-c-mgt_krakow-nat-hide, ip: [172.16.203.1]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.16.203.1"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-cheewu" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-cheewu"
  description  = "role: pr-c-mgt_lcw-cheewu, ip: [10.1.83.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-garethdawson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-garethdawson"
  description  = "role: pr-c-mgt_lcw-garethdawson, ip: [10.1.82.139]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.139"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-jesusingh" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-jesusingh"
  description  = "role: pr-c-mgt_lcw-jesusingh, ip: [10.1.82.136]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.136"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-mattcharlton" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-mattcharlton"
  description  = "role: pr-c-mgt_lcw-mattcharlton, ip: [10.1.83.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-scottbeadsley" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-scottbeadsley"
  description  = "role: pr-c-mgt_lcw-scottbeadsley, ip: [10.1.82.129]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.129"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-timwhaley" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-timwhaley"
  description  = "role: pr-c-mgt_lcw-timwhaley, ip: [10.1.82.156]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.156"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-shanwazmalik" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-shanwazmalik"
  description  = "role: pr-c-mgt_lcw-shanwazmalik, ip: [10.1.82.145]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.145"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-stephencarnall" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-stephencarnall"
  description  = "role: pr-c-mgt_lcw-stephencarnall, ip: [10.1.83.3]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.3"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-wallboardpc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-wallboardpc1"
  description  = "role: pr-c-mgt_lcw-wallboardpc1, ip: [10.1.82.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.132"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-wallboardpc2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-wallboardpc2"
  description  = "role: pr-c-mgt_lcw-wallboardpc2, ip: [10.1.83.2]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.2"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-wallboardpc3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-wallboardpc3"
  description  = "role: pr-c-mgt_lcw-wallboardpc3, ip: [10.1.83.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-alexandroschristias" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-alexandroschristias"
  description  = "role: pr-c-mgt_lcw-alexandroschristias, ip: [10.1.82.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-serveropsmonpc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-serveropsmonpc"
  description  = "role: pr-c-mgt_lcw-serveropsmonpc, ip: [10.1.82.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-andrewfurnival" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-andrewfurnival"
  description  = "role: CHG0034017, ip: [10.180.18.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-johnnoel2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-johnnoel2"
  description  = "role: pr-c-mgt_lcw-johnnoel2, ip: [10.1.82.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-johnnoel" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-johnnoel"
  description  = "role: pr-c-mgt_lcw-johnnoel, ip: [10.1.83.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.69"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_georgepetrouis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_georgepetrouis"
  description  = "role: pr-c-mgt_georgepetrouis, ip: [10.1.83.79]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.79"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ianrichards" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ianrichards"
  description  = "role: pr-c-mgt_ianrichards, ip: [10.1.83.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_jamesgirvan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_jamesgirvan"
  description  = "role: pr-c-mgt_jamesgirvan, ip: [10.1.82.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_jarrodsmithers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_jarrodsmithers"
  description  = "role: pr-c-mgt_jarrodsmithers, ip: [10.1.83.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_johnnoel" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_johnnoel"
  description  = "role: pr-c-mgt_johnnoel, ip: [10.1.83.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.69"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_neilwilson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_neilwilson"
  description  = "role: pr-c-mgt_neilwilson, ip: [10.1.83.67]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.67"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_richardsanderson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_richardsanderson"
  description  = "role: pr-c-mgt_richardsanderson, ip: [10.1.83.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-matthayman" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-matthayman"
  description  = "role: pr-c-mgt_lcw-matthayman, ip: [10.1.82.154]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.154"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-byrongalietta2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-byrongalietta2"
  description  = "role: pr-c-mgt_who-byrongalietta2, ip: [10.1.112.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.250"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_whg-ltp-10-1-83-84" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_whg-ltp-10-1-83-84"
  description  = "role: pr-c-mgt_whg-ltp-10-1-83-84, ip: [10.1.83.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-garethdawson2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-garethdawson2"
  description  = "role: pr-c-mgt_lcw-garethdawson2, ip: [10.1.87.79]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.87.79"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gib-catalinmerluscadesk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gib-catalinmerluscadesk"
  description  = "role: pr-c-mgt_gib-catalinmerluscadesk, ip: [10.180.18.128]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.128"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-connormcnally" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-connormcnally"
  description  = "role: pr-c-mgt_lcw-connormcnally, ip: [10.1.83.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-cmcmullen" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-cmcmullen"
  description  = "role: pr-c-mgt_lcw-cmcmullen, ip: [10.1.82.232]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.232"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-danielosielczak" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-danielosielczak"
  description  = "role: CHG0086299, ip: [10.1.82.121]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.121"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-joserenjikombarakaran" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-joserenjikombarakaran"
  description  = "role: pr-c-mgt_lcw-joserenjikombarakaran, ip: [10.1.82.137]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.137"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_usr-lcw-nbottomley" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_usr-lcw-nbottomley"
  description  = "role: pr-c-mgt_usr-lcw-nbottomley, ip: [10.1.86.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-1-83-229" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-1-83-229"
  description  = "role: pr-c-mgt_10-1-83-229, ip: [10.1.83.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-peteredwards" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-peteredwards"
  description  = "role: pr-c-mgt_lcw-peteredwards, ip: [10.1.82.91]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.91"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibnsm01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibnsm01"
  description  = "role: pr-c-mgt_gibnsm01, ip: [10.180.193.232]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.193.232"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1nsm-ha" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1nsm-ha"
  description  = "role: pr-c-mgt_sc1nsm-ha, ip: [10.120.193.240]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.240"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1nsm01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1nsm01"
  description  = "role: pr-c-mgt_sc1nsm01, ip: [10.120.193.232]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.232"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1nsm01-ha" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1nsm01-ha"
  description  = "role: pr-c-mgt_sc1nsm01-ha, ip: [10.120.193.241]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.241"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1nsm02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1nsm02"
  description  = "role: pr-c-mgt_sc1nsm02, ip: [10.120.193.233]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.233"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1nsm02-ha" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1nsm02-ha"
  description  = "role: pr-c-mgt_sc1nsm02-ha, ip: [10.120.193.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-brs-ise01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-brs-ise01"
  description  = "role: pr-c-mgt_uk-brs-ise01, ip: [10.210.194.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-sc1-ise01-pre-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-sc1-ise01-pre-vmc"
  description  = "role: pr-c-mgt_uk-sc1-ise01-pre-vmc, ip: [10.120.194.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcdb03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcdb03"
  description  = "role: pr-c-mgt_sc1uxprcdb03, ip: [10.120.143.111]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.111"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcdb04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcdb04"
  description  = "role: pr-c-mgt_sc1uxprcdb04, ip: [10.120.143.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-serviceguard-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-serviceguard-vip"
  description  = "role: pr-c-mgt_scc-serviceguard-vip, ip: [10.120.143.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxrdk-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxrdk-prod-williamhill-plc"
  description  = "role: pr-c-mgt_sc1uxrdk-prod-williamhill-plc, ip: [10.120.163.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_capacitymonitoring" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_capacitymonitoring"
  description  = "role: pr-c-mgt_capacitymonitoring, ip: [10.1.83.136/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.136/29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-steveibbotson2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-steveibbotson2"
  description  = "role: pr-c-mgt_lcw-steveibbotson2, ip: [10.1.53.227]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.53.227"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-gavinjohnson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-gavinjohnson"
  description  = "role: pr-c-mgt_who-gavinjohnson, ip: [10.17.100.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-raymondstrose" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-raymondstrose"
  description  = "role: pr-c-mgt_who-raymondstrose, ip: [10.17.100.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-robrussell" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-robrussell"
  description  = "role: pr-c-mgt_who-robrussell, ip: [10.1.87.168]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.87.168"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-robrussell3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-robrussell3"
  description  = "role: pr-c-mgt_who-robrussell3, ip: [10.1.18.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-jayperrikrishnaiah" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-jayperrikrishnaiah"
  description  = "role: pr-c-mgt_dba-jayperrikrishnaiah, ip: [10.1.82.104]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.104"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-keithbrailey" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-keithbrailey"
  description  = "role: pr-c-mgt_dba-keithbrailey, ip: [10.1.82.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-mattprice" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-mattprice"
  description  = "role: pr-c-mgt_dba-mattprice, ip: [10.1.82.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-nickhowe" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-nickhowe"
  description  = "role: pr-c-mgt_dba-nickhowe, ip: [10.1.82.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-oliverallan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-oliverallan"
  description  = "role: pr-c-mgt_dba-oliverallan, ip: [10.1.82.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-oliverallan2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-oliverallan2"
  description  = "role: pr-c-mgt_dba-oliverallan2, ip: [10.1.74.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.60"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-piotradamiak" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-piotradamiak"
  description  = "role: pr-c-mgt_dba-piotradamiak, ip: [10.1.82.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.199"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-richardanthony" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-richardanthony"
  description  = "role: pr-c-mgt_dba-richardanthony, ip: [10.1.82.117]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.117"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-richardanthony2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-richardanthony2"
  description  = "role: pr-c-mgt_dba-richardanthony2, ip: [10.1.74.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-stephenwood" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-stephenwood"
  description  = "role: pr-c-mgt_dba-stephenwood, ip: [10.1.82.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-tobyhenderson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-tobyhenderson"
  description  = "role: pr-c-mgt_dba-tobyhenderson, ip: [10.1.74.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-tobyhenderson2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-tobyhenderson2"
  description  = "role: pr-c-mgt_dba-tobyhenderson2, ip: [10.1.74.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-amarbarot" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-amarbarot"
  description  = "role: pr-c-mgt_dba-amarbarot, ip: [10.1.82.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-stephendenham" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-stephendenham"
  description  = "role: pr-c-mgt_who-stephendenham, ip: [10.180.20.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-miquel-polonio" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-miquel-polonio"
  description  = "role: CHG0065418, ip: [10.180.18.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-jamesfryer" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-jamesfryer"
  description  = "role: pr-c-mgt_stj-jamesfryer, ip: [10.1.74.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-william-palfreman" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-william-palfreman"
  description  = "role: pr-c-mgt_stj-william-palfreman, ip: [10.1.74.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-joshshepheard" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-joshshepheard"
  description  = "role: CHG0092541, ip: [10.1.82.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_is-architecture" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_is-architecture"
  description  = "role: pr-c-mgt_is-architecture, ip: [10.1.21.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.21.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wh0000669" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wh0000669"
  description  = "role: pr-c-mgt_wh0000669, ip: [10.1.112.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-amarbarot" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-amarbarot"
  description  = "role: pr-c-mgt_stj-amarbarot, ip: [10.1.74.111]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.111"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_bg-borislavgergovski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_bg-borislavgergovski"
  description  = "role: pr-c-mgt_bg-borislavgergovski, ip: [10.53.32.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_bg-georgibukolski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_bg-georgibukolski"
  description  = "role: pr-c-mgt_bg-georgibukolski, ip: [10.53.32.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-paweltulowiecki" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-paweltulowiecki"
  description  = "role: pr-c-mgt_krk-paweltulowiecki, ip: [10.55.0.88]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.88"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dbaworkstation1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dbaworkstation1"
  description  = "role: pr-c-mgt_dbaworkstation1, ip: [10.55.1.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.1.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dbaworkstation2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dbaworkstation2"
  description  = "role: pr-c-mgt_dbaworkstation2, ip: [10.55.0.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.0.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_dba-garydennis-ip2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_dba-garydennis-ip2"
  description  = "role: pr-c-mgt_dba-garydennis-ip2, ip: [10.1.70.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.70.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-paweltulowiecki2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-paweltulowiecki2"
  description  = "role: CHG0116788, ip: [10.55.14.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_whol5000000" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_whol5000000"
  description  = "role: pr-c-mgt_whol5000000, ip: [10.180.19.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_kotlarska_cloudteam" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_kotlarska_cloudteam"
  description  = "role: pr-c-mgt_kotlarska_cloudteam, ip: [10.55.13.240/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.13.240/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_rod-merrick-pc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_rod-merrick-pc"
  description  = "role: pr-c-mgt_rod-merrick-pc, ip: [10.3.20.6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.20.6"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-duartedecarvalho-wifi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-duartedecarvalho-wifi"
  description  = "role: pr-c-mgt_krk-duartedecarvalho-wifi, ip: [10.55.227.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.227.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprnap43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprnap43"
  description  = "role: pr-c-mgt_sc1uxprnap43, ip: [10.120.146.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprnap44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprnap44"
  description  = "role: pr-c-mgt_sc1uxprnap44, ip: [10.120.146.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprnap43-ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprnap43-ilo"
  description  = "role: pr-c-mgt_sc1uxprnap43-ilo, ip: [10.120.130.174]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.174"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprnap44-ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprnap44-ilo"
  description  = "role: pr-c-mgt_sc1uxprnap44-ilo, ip: [10.120.80.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.80.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-mateuszstarzec-wifi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-mateuszstarzec-wifi"
  description  = "role: pr-c-mgt_krk-mateuszstarzec-wifi, ip: [10.55.224.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.224.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_san-mgmt-network2-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_san-mgmt-network2-27"
  description  = "role: pr-c-mgt_san-mgmt-network2-27, ip: [10.120.139.224/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.139.224/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_san-mgt-network-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_san-mgt-network-27"
  description  = "role: pr-c-mgt_san-mgt-network-27, ip: [10.120.143.160/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.160/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vcenter-sddc-18-200-66-116-vmwarevmc-com" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vcenter-sddc-18-200-66-116-vmwarevmc-com"
  description  = "role: pr-c-mgt_vcenter-sddc-18-200-66-116-vmwarevmc-com, ip: [10.126.62.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.62.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmcrtprapvro01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmcrtprapvro01-prod-williamhill-plc"
  description  = "role: pr-c-mgt_vmcrtprapvro01-prod-williamhill-plc, ip: [10.233.0.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.233.0.250"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmcrtdrapvro01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmcrtdrapvro01-prod-williamhill-plc"
  description  = "role: pr-c-mgt_vmcrtdrapvro01-prod-williamhill-plc, ip: [10.233.11.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.233.11.250"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1ngprcmg001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1ngprcmg001"
  description  = "role: pr-c-mgt_sc1ngprcmg001, ip: [10.120.139.234]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.139.234"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1ngprcmg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1ngprcmg002"
  description  = "role: pr-c-mgt_sc1ngprcmg002, ip: [10.120.139.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.139.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-storage-subnet2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-storage-subnet2"
  description  = "role: pr-c-mgt_brs-storage-subnet2, ip: [10.210.143.160/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.143.160/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn78" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn78"
  description  = "role: pr-c-mgt_sc1uxpremn78, ip: [10.120.163.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1-cx-cde-mgmt-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-cx-cde-mgmt-lan"
  description  = "role: CHG0068928, ip: [10.121.10.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-120-146-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-120-146-15"
  description  = "role: pr-c-mgt_10-120-146-15, ip: [10.120.146.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-120-146-16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-120-146-16"
  description  = "role: pr-c-mgt_10-120-146-16, ip: [10.120.146.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprrdb001-nic" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprrdb001-nic"
  description  = "role: pr-c-mgt_sc1uxprrdb001-nic, ip: [10.120.180.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprrdb002-nic" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprrdb002-nic"
  description  = "role: pr-c-mgt_sc1uxprrdb002-nic, ip: [10.120.180.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprrdb001_ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprrdb001_ilo"
  description  = "role: pr-c-mgt_sc1uxprrdb001_ilo, ip: [10.120.130.163]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.163"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprrdb002_ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprrdb002_ilo"
  description  = "role: pr-c-mgt_sc1uxprrdb002_ilo, ip: [10.120.130.192]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.192"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_emailhost01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_emailhost01"
  description  = "role: pr-c-mgt_emailhost01, ip: [10.120.33.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_emailhost02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_emailhost02"
  description  = "role: pr-c-mgt_emailhost02, ip: [10.120.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_emailhost03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_emailhost03"
  description  = "role: pr-c-mgt_emailhost03, ip: [10.210.33.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.33.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_emailhost04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_emailhost04"
  description  = "role: pr-c-mgt_emailhost04, ip: [10.210.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_emailhost05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_emailhost05"
  description  = "role: pr-c-mgt_emailhost05, ip: [10.180.33.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.33.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_emailhost06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_emailhost06"
  description  = "role: pr-c-mgt_emailhost06, ip: [10.180.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sd_rdp_pc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sd_rdp_pc"
  description  = "role: pr-c-mgt_sd_rdp_pc, ip: [10.1.26.139]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.26.139"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wh0003111_proofpoint_support" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wh0003111_proofpoint_support"
  description  = "role: pr-c-mgt_wh0003111_proofpoint_support, ip: [10.1.83.147]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.147"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_systems_support" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_systems_support"
  description  = "role: pr-c-mgt_systems_support, ip: [172.16.41.192/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.16.41.192/26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_service_desk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_service_desk"
  description  = "role: pr-c-mgt_service_desk, ip: [10.1.83.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.0/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_infosec" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_infosec"
  description  = "role: pr-c-mgt_infosec, ip: [10.1.82.48/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.48/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scr_ron_jackson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scr_ron_jackson"
  description  = "role: pr-c-mgt_scr_ron_jackson, ip: [10.1.144.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.144.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_rda-andymorris" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_rda-andymorris"
  description  = "role: pr-c-mgt_rda-andymorris, ip: [10.1.22.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stjohns_rda_pc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stjohns_rda_pc"
  description  = "role: pr-c-mgt_stjohns_rda_pc, ip: [10.1.22.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wh0002011_stj_ops" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wh0002011_stj_ops"
  description  = "role: pr-c-mgt_wh0002011_stj_ops, ip: [10.1.22.238]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.238"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-gibraltar-it" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-gibraltar-it"
  description  = "role: pr-c-mgt_who-gibraltar-it, ip: [10.17.100.64/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.64/26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_adg-hagairazmovich" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_adg-hagairazmovich"
  description  = "role: pr-c-mgt_adg-hagairazmovich, ip: [10.51.49.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.49.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_adg-ofirariel" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_adg-ofirariel"
  description  = "role: pr-c-mgt_adg-ofirariel, ip: [10.51.49.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.49.23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_adg-amirmatzas" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_adg-amirmatzas"
  description  = "role: pr-c-mgt_adg-amirmatzas, ip: [10.51.49.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.49.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_adg-eyalzarchi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_adg-eyalzarchi"
  description  = "role: pr-c-mgt_adg-eyalzarchi, ip: [10.51.48.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.48.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wh5000414" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wh5000414"
  description  = "role: pr-c-mgt_wh5000414, ip: [10.53.32.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wh5000560" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wh5000560"
  description  = "role: pr-c-mgt_wh5000560, ip: [10.53.32.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wh5000589" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wh5000589"
  description  = "role: pr-c-mgt_wh5000589, ip: [10.53.32.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.133"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wh5001304" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wh5001304"
  description  = "role: pr-c-mgt_wh5001304, ip: [10.53.32.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.120"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wh5001303" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wh5001303"
  description  = "role: pr-c-mgt_wh5001303, ip: [10.53.32.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wh5001302" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wh5001302"
  description  = "role: pr-c-mgt_wh5001302, ip: [10.53.33.119]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.33.119"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wh5001360" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wh5001360"
  description  = "role: pr-c-mgt_wh5001360, ip: [10.53.32.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_james_drake_pc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_james_drake_pc"
  description  = "role: pr-c-mgt_james_drake_pc, ip: [10.1.82.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_usr-sof-dimitarzafirov" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_usr-sof-dimitarzafirov"
  description  = "role: pr-c-mgt_usr-sof-dimitarzafirov, ip: [10.53.33.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.33.120"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gubux1041" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gubux1041"
  description  = "role: pr-c-mgt_gubux1041, ip: [10.180.131.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.131.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gubux1042" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gubux1042"
  description  = "role: pr-c-mgt_gubux1042, ip: [10.180.131.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.131.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gubux1043" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gubux1043"
  description  = "role: pr-c-mgt_gubux1043, ip: [10.180.131.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.131.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gubux1044" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gubux1044"
  description  = "role: pr-c-mgt_gubux1044, ip: [10.180.131.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.131.23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gubux1045" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gubux1045"
  description  = "role: pr-c-mgt_gubux1045, ip: [10.180.131.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.131.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gubux1046" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gubux1046"
  description  = "role: pr-c-mgt_gubux1046, ip: [10.180.131.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.131.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gubux1047" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gubux1047"
  description  = "role: pr-c-mgt_gubux1047, ip: [10.180.131.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.131.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-nialljoseph" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-nialljoseph"
  description  = "role: CHG0115760, ip: [10.1.82.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-nessus-man-poc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-nessus-man-poc"
  description  = "role: pr-c-mgt_scc-nessus-man-poc, ip: [10.120.143.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-nessus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-nessus"
  description  = "role: CHG0017431, ip: [10.120.143.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprodb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprodb001"
  description  = "role: CHG0112168, ip: [10.120.146.83]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.83"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprodb002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprodb002"
  description  = "role: CHG0112168, ip: [10.120.146.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.84"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprodb001_ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprodb001_ilo"
  description  = "role: CHG0112168, ip: [10.120.130.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprodb002_ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprodb002_ilo"
  description  = "role: CHG0112168, ip: [10.120.130.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.133"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brswnprcmg41-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brswnprcmg41-prod-williamhill-plc"
  description  = "role: CHG0115599, ip: [10.210.141.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.141.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brswnprcmg42-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brswnprcmg42-prod-williamhill-plc"
  description  = "role: CHG0115599, ip: [10.210.141.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.141.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brswnprcmg43-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brswnprcmg43-prod-williamhill-plc"
  description  = "role: CHG0115599, ip: [10.210.141.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.141.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brswnprcmg44-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brswnprcmg44-prod-williamhill-plc"
  description  = "role: CHG0115599, ip: [10.210.141.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.141.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-55-12-93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-55-12-93"
  description  = "role: pr-c-mgt_10-55-12-93, ip: [10.55.12.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.12.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn10"
  description  = "role: CHG0116778, ip: [10.120.163.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn11"
  description  = "role: CHG0116778, ip: [10.120.163.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn12"
  description  = "role: CHG0116778, ip: [10.120.163.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn13"
  description  = "role: CHG0116778, ip: [10.120.163.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn15"
  description  = "role: CHG0116778, ip: [10.120.163.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn105" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn105"
  description  = "role: CHG0116778, ip: [10.120.163.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn106"
  description  = "role: CHG0116778, ip: [10.120.163.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn107"
  description  = "role: CHG0116778, ip: [10.120.163.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn108" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn108"
  description  = "role: CHG0116778, ip: [10.120.163.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn120" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn120"
  description  = "role: CHG0116778, ip: [10.120.163.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.120"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn121" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn121"
  description  = "role: CHG0116778, ip: [10.120.163.121]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.121"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsuxdrrdb04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsuxdrrdb04"
  description  = "role: pr-c-mgt_brsuxdrrdb04, ip: [10.200.4.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.200.4.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprrdb01-tempip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprrdb01-tempip"
  description  = "role: CHG0118285, ip: [10.120.180.137]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.137"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprrdb02-tempip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprrdb02-tempip"
  description  = "role: CHG0118285, ip: [10.120.180.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprrdb01-ilo-rh6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprrdb01-ilo-rh6"
  description  = "role: pr-c-mgt_sc1uxprrdb01-ilo-rh6, ip: [10.120.130.177]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.177"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprrdb02-ilo-rh6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprrdb02-ilo-rh6"
  description  = "role: pr-c-mgt_sc1uxprrdb02-ilo-rh6, ip: [10.120.130.193]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.193"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpreap237" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpreap237"
  description  = "role: pr-c-mgt_sc1uxpreap237, ip: [10.120.163.237]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.237"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpreap238" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpreap238"
  description  = "role: pr-c-mgt_sc1uxpreap238, ip: [10.120.163.238]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.238"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-120-140-200slash30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-120-140-200slash30"
  description  = "role: pr-c-mgt_10-120-140-200slash30, ip: [10.120.140.200/30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.200/30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpremn74-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpremn74-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.120.163.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpremn75-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpremn75-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.120.163.123]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.123"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpremn77-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpremn77-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.120.163.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpremn78-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpremn78-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.120.163.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6wnpremn74-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6wnpremn74-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.125]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.125"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6wnpremn75-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6wnpremn75-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.126]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.126"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6wnpremn77-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6wnpremn77-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6wnpremn78-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6wnpremn78-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6wnpremn79-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6wnpremn79-prod-williamhill-plc"
  description  = "role: CHG0140962, ip: [10.112.12.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_cust-zabprx-prod-01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_cust-zabprx-prod-01"
  description  = "role: CHG0121232, ip: [10.196.201.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.196.201.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_cust-zabprx-prod-01-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_cust-zabprx-prod-01-2"
  description  = "role: pr-c-mgt_cust-zabprx-prod-01-2, ip: [172.16.202.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.16.202.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-195-201-171" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-195-201-171"
  description  = "role: CHG0137286, ip: [10.195.201.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.195.201.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_172-16-201-171" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_172-16-201-171"
  description  = "role: CHG0137286, ip: [172.16.201.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.16.201.171"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1ux304" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1ux304"
  description  = "role: pr-c-mgt_sc1ux304, ip: [10.120.143.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1ux305" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1ux305"
  description  = "role: pr-c-mgt_sc1ux305, ip: [10.120.143.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.120"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1ux307" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1ux307"
  description  = "role: pr-c-mgt_sc1ux307, ip: [10.120.143.123]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.123"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprxdb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprxdb01"
  description  = "role: pr-c-mgt_sc1uxprxdb01, ip: [10.120.133.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.133.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprxdb02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprxdb02"
  description  = "role: pr-c-mgt_sc1uxprxdb02, ip: [10.120.133.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.133.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_labm1001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_labm1001"
  description  = "role: CHG0126163, ip: [10.61.11.1]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.61.11.1"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_labm1002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_labm1002"
  description  = "role: CHG0126163, ip: [10.61.11.2]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.61.11.2"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_labm1003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_labm1003"
  description  = "role: CHG0126163, ip: [10.61.11.3]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.61.11.3"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_labm1009" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_labm1009"
  description  = "role: CHG0126733, ip: [10.61.11.9]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.61.11.9"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_usnv-ahuts-dwx" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_usnv-ahuts-dwx"
  description  = "role: pr-c-mgt_usnv-ahuts-dwx, ip: [10.18.11.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_usnv-chmoo-lwx" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_usnv-chmoo-lwx"
  description  = "role: pr-c-mgt_usnv-chmoo-lwx, ip: [10.18.11.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_usnv-rmusni-dwx" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_usnv-rmusni-dwx"
  description  = "role: pr-c-mgt_usnv-rmusni-dwx, ip: [10.18.11.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_usnv-scron-dw7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_usnv-scron-dw7"
  description  = "role: pr-c-mgt_usnv-scron-dw7, ip: [10.18.11.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_usnv-tring-dwx" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_usnv-tring-dwx"
  description  = "role: pr-c-mgt_usnv-tring-dwx, ip: [10.18.11.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wh0004101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wh0004101"
  description  = "role: pr-c-mgt_wh0004101, ip: [10.18.11.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wh0004111" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wh0004111"
  description  = "role: pr-c-mgt_wh0004111, ip: [10.18.11.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_us-aaronhutsell" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_us-aaronhutsell"
  description  = "role: CHG0135451, ip: [10.18.11.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_us-bartopiola" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_us-bartopiola"
  description  = "role: CHG0135451, ip: [10.18.11.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_us-chrismoore" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_us-chrismoore"
  description  = "role: CHG0135451, ip: [10.18.11.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_us-reinermusni" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_us-reinermusni"
  description  = "role: CHG0135451, ip: [10.18.11.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_us-roderickvilla" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_us-roderickvilla"
  description  = "role: CHG0135451, ip: [10.18.11.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_us-seancronan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_us-seancronan"
  description  = "role: CHG0135451, ip: [10.18.11.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_us-tommyringstad" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_us-tommyringstad"
  description  = "role: CHG0135451, ip: [10.18.11.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.11.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-san-sw5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-san-sw5"
  description  = "role: pr-c-mgt_scc-san-sw5, ip: [10.120.143.168]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.168"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-san-sw6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-san-sw6"
  description  = "role: pr-c-mgt_scc-san-sw6, ip: [10.120.143.169]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.169"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-sc1-ise02-pre-vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-sc1-ise02-pre-vmc"
  description  = "role: CHG0137261, ip: [10.120.194.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-brs-ise02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-brs-ise02"
  description  = "role: CHG0137261, ip: [10.210.194.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gi-mpl-ise01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gi-mpl-ise01"
  description  = "role: CHG0137261, ip: [10.180.194.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.194.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-sc1-ise01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-sc1-ise01"
  description  = "role: CHG0145266, ip: [10.120.192.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-sc1-ise02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-sc1-ise02"
  description  = "role: CHG0145266, ip: [10.120.192.136]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.136"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmc-whc-dev-10-126-76-0_22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmc-whc-dev-10-126-76-0_22"
  description  = "role: pr-c-mgt_vmc-whc-dev-10-126-76-0_22, ip: [10.126.76.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.76.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_bfawnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_bfawnpredc01"
  description  = "role: pr-c-mgt_bfawnpredc01, ip: [10.56.9.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.9.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brswnpredc01_ip_10-210-194-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brswnpredc01_ip_10-210-194-11"
  description  = "role: CHG0141790, ip: [10.210.194.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brswnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brswnpredc02"
  description  = "role: pr-c-mgt_brswnpredc02, ip: [10.210.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brswnpredc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brswnpredc03"
  description  = "role: pr-c-mgt_brswnpredc03, ip: [10.210.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibwnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibwnpredc02"
  description  = "role: pr-c-mgt_gibwnpredc02, ip: [10.180.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibwnpredc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibwnpredc03"
  description  = "role: pr-c-mgt_gibwnpredc03, ip: [10.180.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krawnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krawnpredc01"
  description  = "role: pr-c-mgt_krawnpredc01, ip: [10.55.9.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.9.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krawnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krawnpredc02"
  description  = "role: pr-c-mgt_krawnpredc02, ip: [10.55.9.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.9.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6wnpredc01-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6wnpredc01-new"
  description  = "role: pr-c-mgt_ld6wnpredc01-new, ip: [10.19.2.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6wnpredc02-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6wnpredc02-new"
  description  = "role: pr-c-mgt_ld6wnpredc02-new, ip: [10.19.2.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_mnlwnpredc02_ip_10-123-197-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_mnlwnpredc02_ip_10-123-197-11"
  description  = "role: CHG0141790, ip: [10.123.197.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.197.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_mnlwnpredc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_mnlwnpredc03"
  description  = "role: pr-c-mgt_mnlwnpredc03, ip: [10.123.197.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.197.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpredc01_ip_10-120-194-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpredc01_ip_10-120-194-11"
  description  = "role: pr-c-mgt_sc1wnpredc01_ip_10-120-194-11, ip: [10.120.194.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpredc02_ip_10-120-194-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpredc02_ip_10-120-194-12"
  description  = "role: pr-c-mgt_sc1wnpredc02_ip_10-120-194-12, ip: [10.120.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpredc04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpredc04"
  description  = "role: pr-c-mgt_sc1wnpredc04, ip: [10.120.194.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpredc05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpredc05"
  description  = "role: pr-c-mgt_sc1wnpredc05, ip: [10.120.194.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpredc08" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpredc08"
  description  = "role: pr-c-mgt_sc1wnpredc08, ip: [10.120.194.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sofwnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sofwnpredc01"
  description  = "role: pr-c-mgt_sofwnpredc01, ip: [10.53.98.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.98.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sofwnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sofwnpredc02"
  description  = "role: pr-c-mgt_sofwnpredc02, ip: [10.53.98.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.98.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsapprcmg002-group-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsapprcmg002-group-williamhill-plc"
  description  = "role: CHG0142765, ip: [10.210.163.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn002"
  description  = "role: CHG0142763, ip: [10.120.163.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn003"
  description  = "role: CHG0142763, ip: [10.120.163.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_splunkdeployment-sc1-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_splunkdeployment-sc1-prod-williamhill-plc"
  description  = "role: CHG0142763, ip: [10.120.163.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprbkms01"
  description  = "role: CHG0112231, ip: [10.120.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprbkms02"
  description  = "role: CHG0112231, ip: [10.120.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprbkcs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprbkcs01"
  description  = "role: pr-c-mgt_sc1wnprbkcs01, ip: [10.120.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibuxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibuxprbkms01"
  description  = "role: CHG0112231, ip: [10.180.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibuxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibuxprbkms02"
  description  = "role: CHG0112231, ip: [10.180.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6uxprbkms03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6uxprbkms03"
  description  = "role: CHG0112231, ip: [10.112.46.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6uxprbkms04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6uxprbkms04"
  description  = "role: CHG0112231, ip: [10.112.46.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6wnprbkcs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6wnprbkcs01"
  description  = "role: CHG0112231, ip: [10.112.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6uxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6uxprbkms01"
  description  = "role: CHG0112231, ip: [10.112.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6uxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6uxprbkms02"
  description  = "role: CHG0112231, ip: [10.112.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn002-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn002-prod-williamhill-plc"
  description  = "role: pr-c-mgt_sc1uxpremn002-prod-williamhill-plc, ip: [10.120.163.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn003-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn003-prod-williamhill-plc"
  description  = "role: pr-c-mgt_sc1uxpremn003-prod-williamhill-plc, ip: [10.120.163.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn004-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn004-prod-williamhill-plc"
  description  = "role: CHG0108969, ip: [10.120.163.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.134"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpreap239" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpreap239"
  description  = "role: pr-c-mgt_sc1uxpreap239, ip: [10.120.163.239]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.239"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpreap242" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpreap242"
  description  = "role: pr-c-mgt_sc1uxpreap242, ip: [10.120.163.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxrdk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxrdk"
  description  = "role: pr-c-mgt_sc1uxrdk, ip: [10.120.163.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsux910" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsux910"
  description  = "role: pr-c-mgt_brsux910, ip: [10.1.28.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibux910" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibux910"
  description  = "role: pr-c-mgt_gibux910, ip: [10.180.163.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6uxpreds01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6uxpreds01"
  description  = "role: pr-c-mgt_ld6uxpreds01, ip: [10.112.12.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpreds01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpreds01"
  description  = "role: CHG0017590, ip: [10.120.194.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-121-5-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-121-5-0slash24"
  description  = "role: pr-c-mgt_10-121-5-0slash24, ip: [10.121.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_10-121-7-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_10-121-7-0slash24"
  description  = "role: pr-c-mgt_10-121-7-0slash24, ip: [10.121.7.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.7.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremg25-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremg25-prod-williamhill-plc"
  description  = "role: pr-c-mgt_sc1uxpremg25-prod-williamhill-plc, ip: [10.120.163.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprcmn001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprcmn001"
  description  = "role: pr-c-mgt_sc1uxprcmn001, ip: [10.120.163.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsns01"
  description  = "role: pr-c-mgt_brsns01, ip: [10.210.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsns02"
  description  = "role: pr-c-mgt_brsns02, ip: [10.210.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibns01"
  description  = "role: pr-c-mgt_gibns01, ip: [10.180.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gibns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gibns02"
  description  = "role: pr-c-mgt_gibns02, ip: [10.180.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sccns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sccns01"
  description  = "role: pr-c-mgt_sccns01, ip: [10.120.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sccns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sccns02"
  description  = "role: pr-c-mgt_sccns02, ip: [10.120.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6ns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6ns01"
  description  = "role: pr-c-mgt_ld6ns01, ip: [10.112.208.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.208.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6ns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6ns02"
  description  = "role: pr-c-mgt_ld6ns02, ip: [10.112.208.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.208.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-brs-ns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-brs-ns01"
  description  = "role: pr-c-mgt_uk-brs-ns01, ip: [10.210.193.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-sc1-ns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-sc1-ns01"
  description  = "role: pr-c-mgt_uk-sc1-ns01, ip: [10.120.193.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-wsus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-wsus"
  description  = "role: pr-c-mgt_stj-wsus, ip: [10.110.163.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.110.163.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnprein07" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnprein07"
  description  = "role: CHG0017174, ip: [10.120.195.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.195.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-tmcm01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-tmcm01"
  description  = "role: CHG0017396, ip: [10.50.3.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.50.3.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_uk-sc1-sm02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_uk-sc1-sm02"
  description  = "role: pr-c-mgt_uk-sc1-sm02, ip: [10.120.163.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ntp001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ntp001"
  description  = "role: CHG00, ip: [10.120.163.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ntp002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ntp002"
  description  = "role: CHG00, ip: [10.120.163.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brs-proofpoint" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brs-proofpoint"
  description  = "role: CHG0012936, ip: [10.210.168.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.168.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scc-mail" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-mail"
  description  = "role: pr-c-mgt_scc-mail, ip: [10.120.67.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.67.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-proofpoint" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-proofpoint"
  description  = "role: CHG0014227, ip: [10.110.168.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.110.168.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsuxpremn65" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsuxpremn65"
  description  = "role: CHG0079749, ip: [10.210.163.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brsuxpremn66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsuxpremn66"
  description  = "role: CHG0079749, ip: [10.210.163.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn65" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn65"
  description  = "role: CHG0079749, ip: [10.120.163.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxpremn66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxpremn66"
  description  = "role: CHG0079749, ip: [10.120.163.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ld6uxpremn13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ld6uxpremn13"
  description  = "role: pr-c-mgt_ld6uxpremn13, ip: [10.112.12.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1wnpremg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1wnpremg002"
  description  = "role: pr-c-mgt_sc1wnpremg002, ip: [10.120.194.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_brswndremg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brswndremg002"
  description  = "role: pr-c-mgt_brswndremg002, ip: [10.210.194.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-asim-ibrahim" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-asim-ibrahim"
  description  = "role: pr-c-mgt_stj-asim-ibrahim, ip: [10.1.74.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-nick-simpson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-nick-simpson"
  description  = "role: pr-c-mgt_stj-nick-simpson, ip: [10.1.74.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-llanosnunez" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-llanosnunez"
  description  = "role: pr-c-mgt_who-llanosnunez, ip: [10.180.19.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-chriswren2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-chriswren2"
  description  = "role: pr-c-mgt_lcw-chriswren2, ip: [10.1.82.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-richardhampshire" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-richardhampshire"
  description  = "role: pr-c-mgt_lcw-richardhampshire, ip: [10.1.82.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-alastairmontgomery" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-alastairmontgomery"
  description  = "role: pr-c-mgt_who-alastairmontgomery, ip: [10.1.74.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-joncandlin" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-joncandlin"
  description  = "role: pr-c-mgt_who-joncandlin, ip: [10.1.74.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-neilbellamy2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-neilbellamy2"
  description  = "role: pr-c-mgt_who-neilbellamy2, ip: [10.180.18.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-chrishall" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-chrishall"
  description  = "role: pr-c-mgt_who-chrishall, ip: [10.1.82.249]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.249"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stj-nathanflynn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stj-nathanflynn"
  description  = "role: pr-c-mgt_stj-nathanflynn, ip: [10.1.74.119]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.119"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-amcadam" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-amcadam"
  description  = "role: pr-c-mgt_who-amcadam, ip: [10.17.8.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-alancatto" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-alancatto"
  description  = "role: INC0401046, ip: [10.1.87.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.87.120"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_gib-karolstatkiewicz" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_gib-karolstatkiewicz"
  description  = "role: pr-c-mgt_gib-karolstatkiewicz, ip: [10.180.19.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.19.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-amcadam2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-amcadam2"
  description  = "role: CHG0092029, ip: [10.1.78.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_infosec-sdavies" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_infosec-sdavies"
  description  = "role: pr-c-mgt_infosec-sdavies, ip: [10.1.82.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_infosec-jmcintyre" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_infosec-jmcintyre"
  description  = "role: pr-c-mgt_infosec-jmcintyre, ip: [10.1.82.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_infosec-sanderson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_infosec-sanderson"
  description  = "role: pr-c-mgt_infosec-sanderson, ip: [10.1.82.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_infosec-sbond1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_infosec-sbond1"
  description  = "role: pr-c-mgt_infosec-sbond1, ip: [10.1.82.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_infosec-sbond" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_infosec-sbond"
  description  = "role: pr-c-mgt_infosec-sbond, ip: [10.1.82.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-summtjain" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-summtjain"
  description  = "role: pr-c-mgt_lcw-summtjain, ip: [10.1.83.233]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.233"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-andrewlongmuir" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-andrewlongmuir"
  description  = "role: pr-c-mgt_lcw-andrewlongmuir, ip: [10.1.83.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-johnsnow" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-johnsnow"
  description  = "role: pr-c-mgt_lcw-johnsnow, ip: [10.1.83.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-davewalsh" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-davewalsh"
  description  = "role: pr-c-mgt_lcw-davewalsh, ip: [10.1.83.139]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.139"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-richthomas" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-richthomas"
  description  = "role: pr-c-mgt_lcw-richthomas, ip: [10.1.83.166]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.166"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-samillingworth" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-samillingworth"
  description  = "role: pr-c-mgt_lcw-samillingworth, ip: [10.1.83.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-stevemoyes" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-stevemoyes"
  description  = "role: pr-c-mgt_lcw-stevemoyes, ip: [10.1.83.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-davidwalshlaptop" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-davidwalshlaptop"
  description  = "role: pr-c-mgt_lcw-davidwalshlaptop, ip: [10.1.83.157]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.157"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-summitjain" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-summitjain"
  description  = "role: pr-c-mgt_lcw-summitjain, ip: [10.1.83.233]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.233"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ia-jennyfarrell" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ia-jennyfarrell"
  description  = "role: pr-c-mgt_ia-jennyfarrell, ip: [10.1.82.157]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.157"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ia-robrussell" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ia-robrussell"
  description  = "role: pr-c-mgt_ia-robrussell, ip: [10.1.82.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ia-steveibbotson" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ia-steveibbotson"
  description  = "role: pr-c-mgt_ia-steveibbotson, ip: [10.1.82.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_lcw-stevenhammersley" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_lcw-stevenhammersley"
  description  = "role: pr-c-mgt_lcw-stevenhammersley, ip: [10.1.82.141]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.141"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_who-cezarygajdzinski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_who-cezarygajdzinski"
  description  = "role: pr-c-mgt_who-cezarygajdzinski, ip: [10.180.18.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scr-group-1st-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scr-group-1st-network"
  description  = "role: CHG0067336, ip: [10.1.144.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.144.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scr-group-2nd-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scr-group-2nd-network"
  description  = "role: CHG0067336, ip: [10.1.148.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.148.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scr-online-1st-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scr-online-1st-network"
  description  = "role: CHG0067336, ip: [10.17.144.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.144.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_scr-online-2nd-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scr-online-2nd-network"
  description  = "role: CHG0067336, ip: [10.17.148.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.148.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wpp-3rd-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wpp-3rd-network"
  description  = "role: CHG0067336, ip: [10.17.100.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.100.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wpp-5th-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wpp-5th-network"
  description  = "role: CHG0067336, ip: [10.180.27.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wpp-6th-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wpp-6th-network"
  description  = "role: CHG0067336, ip: [10.180.18.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wpp-grnd-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wpp-grnd-network"
  description  = "role: CHG0067336, ip: [10.180.20.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wpp-group-3rd-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wpp-group-3rd-network"
  description  = "role: CHG0067336, ip: [10.1.82.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wpp-group-4th-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wpp-group-4th-network"
  description  = "role: CHG0067336, ip: [10.1.86.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_wpp-online-network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wpp-online-network"
  description  = "role: CHG0067336, ip: [10.17.8.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.17.8.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ia-paulsenior" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ia-paulsenior"
  description  = "role: pr-c-mgt_ia-paulsenior, ip: [10.1.83.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ia-elizabethlaing" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ia-elizabethlaing"
  description  = "role: pr-c-mgt_ia-elizabethlaing, ip: [10.1.82.153]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.153"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_usr-tlv-wh5001456" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_usr-tlv-wh5001456"
  description  = "role: pr-c-mgt_usr-tlv-wh5001456, ip: [10.51.49.87]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.51.49.87"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-jakubwalkowicz-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-jakubwalkowicz-lan"
  description  = "role: pr-c-mgt_krk-jakubwalkowicz-lan, ip: [10.55.13.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.13.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-jakubwalkowicz-wifi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-jakubwalkowicz-wifi"
  description  = "role: pr-c-mgt_krk-jakubwalkowicz-wifi, ip: [10.55.225.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.225.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-kzlomanczuk-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-kzlomanczuk-lan"
  description  = "role: pr-c-mgt_krk-kzlomanczuk-lan, ip: [10.55.13.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.13.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-kzlomanczuk-wifi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-kzlomanczuk-wifi"
  description  = "role: pr-c-mgt_krk-kzlomanczuk-wifi, ip: [10.55.225.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.225.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-pzalewski-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-pzalewski-lan"
  description  = "role: pr-c-mgt_krk-pzalewski-lan, ip: [10.55.13.94]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.13.94"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-pzalewski-wifi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-pzalewski-wifi"
  description  = "role: pr-c-mgt_krk-pzalewski-wifi, ip: [10.55.225.94]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.225.94"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-pzurek-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-pzurek-lan"
  description  = "role: pr-c-mgt_krk-pzurek-lan, ip: [10.55.13.157]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.13.157"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_krk-pzurek-wifi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_krk-pzurek-wifi"
  description  = "role: pr-c-mgt_krk-pzurek-wifi, ip: [10.55.225.157]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.225.157"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprbkvs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprbkvs01"
  description  = "role: pr-c-mgt_sc1uxprbkvs01, ip: [10.120.46.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprbkvs02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprbkvs02"
  description  = "role: pr-c-mgt_sc1uxprbkvs02, ip: [10.120.46.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprbkvs03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprbkvs03"
  description  = "role: pr-c-mgt_sc1uxprbkvs03, ip: [10.120.46.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprbkvs04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprbkvs04"
  description  = "role: pr-c-mgt_sc1uxprbkvs04, ip: [10.120.46.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprbkvs05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprbkvs05"
  description  = "role: pr-c-mgt_sc1uxprbkvs05, ip: [10.120.46.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprrdb01-mg" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprrdb01-mg"
  description  = "role: Liability Viewer PDS DB node 1, ip: [10.120.180.166]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.166"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_sc1uxprrdb02-mg" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1uxprrdb02-mg"
  description  = "role: Liability Viewer PDS DB node 2, ip: [10.120.180.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmc-retail-production-vsphere-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmc-retail-production-vsphere-mgmt"
  description  = "role: pr-c-mgt_vmc-retail-production-vsphere-mgmt, ip: [10.126.32.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.32.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmc-retail-production-10-233-0-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmc-retail-production-10-233-0-0s24"
  description  = "role: pr-c-mgt_vmc-retail-production-10-233-0-0s24, ip: [10.233.0.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.233.0.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_vmc-retail-production-services-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmc-retail-production-services-mgmt"
  description  = "role: pr-c-mgt_vmc-retail-production-services-mgmt, ip: [10.156.1.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.1.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_esteem-jumphost-brs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_esteem-jumphost-brs"
  description  = "role: pr-c-mgt_esteem-jumphost-brs, ip: [10.210.39.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.39.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_esteem-jumphost-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_esteem-jumphost-scc"
  description  = "role: pr-c-mgt_esteem-jumphost-scc, ip: [10.120.39.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_citywalk78" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_citywalk78"
  description  = "role: CHG0091835, ip: [10.1.78.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.78.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_stjohns79" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stjohns79"
  description  = "role: CHG0091835, ip: [10.1.79.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.79.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-136-181" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-136-181"
  description  = "role: pr-c-mgt_ip_10-120-136-181, ip: [10.120.136.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-137-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-137-11"
  description  = "role: pr-c-mgt_ip_10-120-137-11, ip: [10.120.137.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.137.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-137-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-137-12"
  description  = "role: pr-c-mgt_ip_10-120-137-12, ip: [10.120.137.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.137.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-14"
  description  = "role: pr-c-mgt_ip_10-120-140-14, ip: [10.120.140.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-194-58" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-194-58"
  description  = "role: pr-c-mgt_ip_10-120-194-58, ip: [10.120.194.58]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.58"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-134-253" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-134-253"
  description  = "role: pr-c-mgt_ip_10-120-134-253, ip: [10.120.134.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.253"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-136-30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-136-30"
  description  = "role: pr-c-mgt_ip_10-120-136-30, ip: [10.120.136.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-163-140" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-163-140"
  description  = "role: pr-c-mgt_ip_10-180-163-140, ip: [10.180.163.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-185" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-185"
  description  = "role: pr-c-mgt_ip_10-120-143-185, ip: [10.120.143.185]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.185"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-118" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-118"
  description  = "role: pr-c-mgt_ip_10-120-163-118, ip: [10.120.163.118]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.118"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-134" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-134"
  description  = "role: pr-c-mgt_ip_10-120-163-134, ip: [10.120.163.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.134"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-89" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-89"
  description  = "role: pr-c-mgt_ip_10-120-163-89, ip: [10.120.163.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-33-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-33-11"
  description  = "role: pr-c-mgt_ip_10-120-33-11, ip: [10.120.33.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-134-246" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-134-246"
  description  = "role: pr-c-mgt_ip_10-120-134-246, ip: [10.120.134.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.246"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-33"
  description  = "role: pr-c-mgt_ip_10-120-163-33, ip: [10.120.163.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-181" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-181"
  description  = "role: pr-c-mgt_ip_10-120-131-181, ip: [10.120.131.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-182" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-182"
  description  = "role: pr-c-mgt_ip_10-120-131-182, ip: [10.120.131.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-183" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-183"
  description  = "role: pr-c-mgt_ip_10-120-131-183, ip: [10.120.131.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-184" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-184"
  description  = "role: pr-c-mgt_ip_10-120-131-184, ip: [10.120.131.184]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.184"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-31"
  description  = "role: pr-c-mgt_ip_10-120-163-31, ip: [10.120.163.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-32"
  description  = "role: pr-c-mgt_ip_10-120-163-32, ip: [10.120.163.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-35"
  description  = "role: pr-c-mgt_ip_10-120-163-35, ip: [10.120.163.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-36"
  description  = "role: pr-c-mgt_ip_10-120-163-36, ip: [10.120.163.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-135" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-135"
  description  = "role: pr-c-mgt_ip_10-120-163-135, ip: [10.120.163.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-200"
  description  = "role: pr-c-mgt_ip_10-120-131-200, ip: [10.120.131.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-201" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-201"
  description  = "role: pr-c-mgt_ip_10-120-131-201, ip: [10.120.131.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-202" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-202"
  description  = "role: pr-c-mgt_ip_10-120-131-202, ip: [10.120.131.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-203" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-203"
  description  = "role: pr-c-mgt_ip_10-120-131-203, ip: [10.120.131.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-204" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-204"
  description  = "role: pr-c-mgt_ip_10-120-131-204, ip: [10.120.131.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-205" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-205"
  description  = "role: pr-c-mgt_ip_10-120-131-205, ip: [10.120.131.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-206" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-206"
  description  = "role: pr-c-mgt_ip_10-120-131-206, ip: [10.120.131.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-207" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-207"
  description  = "role: pr-c-mgt_ip_10-120-131-207, ip: [10.120.131.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.207"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-11"
  description  = "role: pr-c-mgt_ip_10-120-140-11, ip: [10.120.140.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-12"
  description  = "role: pr-c-mgt_ip_10-120-140-12, ip: [10.120.140.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-200"
  description  = "role: pr-c-mgt_ip_10-120-140-200, ip: [10.120.140.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-201" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-201"
  description  = "role: pr-c-mgt_ip_10-120-140-201, ip: [10.120.140.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-202" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-202"
  description  = "role: pr-c-mgt_ip_10-120-140-202, ip: [10.120.140.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-203" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-203"
  description  = "role: pr-c-mgt_ip_10-120-140-203, ip: [10.120.140.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-204" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-204"
  description  = "role: pr-c-mgt_ip_10-120-140-204, ip: [10.120.140.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-205" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-205"
  description  = "role: pr-c-mgt_ip_10-120-140-205, ip: [10.120.140.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-163-145" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-163-145"
  description  = "role: pr-c-mgt_ip_10-180-163-145, ip: [10.180.163.145]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.145"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-194-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-194-12"
  description  = "role: pr-c-mgt_ip_10-120-194-12, ip: [10.120.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-194-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-194-13"
  description  = "role: pr-c-mgt_ip_10-120-194-13, ip: [10.120.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-194-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-194-14"
  description  = "role: pr-c-mgt_ip_10-120-194-14, ip: [10.120.194.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-140-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-140-11"
  description  = "role: pr-c-mgt_ip_10-180-140-11, ip: [10.180.140.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.140.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-140-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-140-12"
  description  = "role: pr-c-mgt_ip_10-180-140-12, ip: [10.180.140.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.140.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-140-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-140-13"
  description  = "role: pr-c-mgt_ip_10-180-140-13, ip: [10.180.140.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.140.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-140-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-140-14"
  description  = "role: pr-c-mgt_ip_10-180-140-14, ip: [10.180.140.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.140.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-140-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-140-15"
  description  = "role: pr-c-mgt_ip_10-180-140-15, ip: [10.180.140.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.140.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-140-16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-140-16"
  description  = "role: pr-c-mgt_ip_10-180-140-16, ip: [10.180.140.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.140.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-13"
  description  = "role: pr-c-mgt_ip_10-120-140-13, ip: [10.120.140.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-15"
  description  = "role: pr-c-mgt_ip_10-120-140-15, ip: [10.120.140.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-16"
  description  = "role: pr-c-mgt_ip_10-120-140-16, ip: [10.120.140.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-140-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-140-11"
  description  = "role: pr-c-mgt_ip_10-210-140-11, ip: [10.210.140.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.140.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-140-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-140-12"
  description  = "role: pr-c-mgt_ip_10-210-140-12, ip: [10.210.140.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.140.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-211-140-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-211-140-11"
  description  = "role: pr-c-mgt_ip_10-211-140-11, ip: [10.211.140.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.211.140.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-212-140-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-212-140-11"
  description  = "role: pr-c-mgt_ip_10-212-140-11, ip: [10.212.140.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.212.140.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-213-140-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-213-140-11"
  description  = "role: pr-c-mgt_ip_10-213-140-11, ip: [10.213.140.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.213.140.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-214-140-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-214-140-11"
  description  = "role: pr-c-mgt_ip_10-214-140-11, ip: [10.214.140.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.214.140.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-215-140-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-215-140-11"
  description  = "role: pr-c-mgt_ip_10-215-140-11, ip: [10.215.140.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.215.140.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-216-140-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-216-140-11"
  description  = "role: pr-c-mgt_ip_10-216-140-11, ip: [10.216.140.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.216.140.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-129-151" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-129-151"
  description  = "role: pr-c-mgt_ip_10-120-129-151, ip: [10.120.129.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-129-151" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-129-151"
  description  = "role: pr-c-mgt_ip_10-180-129-151, ip: [10.180.129.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-163-48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-163-48"
  description  = "role: pr-c-mgt_ip_10-180-163-48, ip: [10.180.163.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-110-163-30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-110-163-30"
  description  = "role: pr-c-mgt_ip_10-110-163-30, ip: [10.110.163.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.110.163.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-139-210" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-139-210"
  description  = "role: pr-c-mgt_ip_10-180-139-210, ip: [10.180.139.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.139.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-30"
  description  = "role: pr-c-mgt_ip_10-120-163-30, ip: [10.120.163.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-41"
  description  = "role: pr-c-mgt_ip_10-120-131-41, ip: [10.120.131.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-131-42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-131-42"
  description  = "role: pr-c-mgt_ip_10-120-131-42, ip: [10.120.131.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-132-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-132-31"
  description  = "role: pr-c-mgt_ip_10-120-132-31, ip: [10.120.132.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-132-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-132-45"
  description  = "role: pr-c-mgt_ip_10-120-132-45, ip: [10.120.132.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-132-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-132-46"
  description  = "role: pr-c-mgt_ip_10-120-132-46, ip: [10.120.132.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-132-32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-132-32"
  description  = "role: pr-c-mgt_ip_10-120-132-32, ip: [10.120.132.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-131" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-131"
  description  = "role: pr-c-mgt_ip_10-120-163-131, ip: [10.120.163.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-82-220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-82-220"
  description  = "role: pr-c-mgt_ip_10-1-82-220, ip: [10.1.82.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-112-230" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-112-230"
  description  = "role: pr-c-mgt_ip_10-1-112-230, ip: [10.1.112.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.112.230"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-21-118" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-21-118"
  description  = "role: pr-c-mgt_ip_10-1-21-118, ip: [10.1.21.118]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.21.118"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-22-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-22-17"
  description  = "role: pr-c-mgt_ip_10-1-22-17, ip: [10.1.22.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-22-181" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-22-181"
  description  = "role: pr-c-mgt_ip_10-1-22-181, ip: [10.1.22.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-22-185" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-22-185"
  description  = "role: pr-c-mgt_ip_10-1-22-185, ip: [10.1.22.185]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.185"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-15"
  description  = "role: pr-c-mgt_ip_10-1-83-15, ip: [10.1.83.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-22-33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-22-33"
  description  = "role: pr-c-mgt_ip_10-1-22-33, ip: [10.1.22.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.22.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-129-69" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-129-69"
  description  = "role: pr-c-mgt_ip_10-180-129-69, ip: [10.180.129.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.69"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-129-70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-129-70"
  description  = "role: pr-c-mgt_ip_10-180-129-70, ip: [10.180.129.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.129.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-129-34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-129-34"
  description  = "role: pr-c-mgt_ip_10-210-129-34, ip: [10.210.129.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-129-35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-129-35"
  description  = "role: pr-c-mgt_ip_10-210-129-35, ip: [10.210.129.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-129-240" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-129-240"
  description  = "role: pr-c-mgt_ip_10-210-129-240, ip: [10.210.129.240]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.129.240"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-163-131" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-163-131"
  description  = "role: pr-c-mgt_ip_10-210-163-131, ip: [10.210.163.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-82-80" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-82-80"
  description  = "role: pr-c-mgt_ip_10-1-82-80, ip: [10.1.82.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-53-33-56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-53-33-56"
  description  = "role: pr-c-mgt_ip_10-53-33-56, ip: [10.53.33.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.33.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-46-35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-46-35"
  description  = "role: pr-c-mgt_ip_10-120-46-35, ip: [10.120.46.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-46-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-46-36"
  description  = "role: pr-c-mgt_ip_10-120-46-36, ip: [10.120.46.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-46-37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-46-37"
  description  = "role: pr-c-mgt_ip_10-120-46-37, ip: [10.120.46.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-46-38" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-46-38"
  description  = "role: pr-c-mgt_ip_10-120-46-38, ip: [10.120.46.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-46-39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-46-39"
  description  = "role: pr-c-mgt_ip_10-120-46-39, ip: [10.120.46.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-172" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-172"
  description  = "role: pr-c-mgt_ip_10-120-143-172, ip: [10.120.143.172]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.172"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-173" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-173"
  description  = "role: pr-c-mgt_ip_10-120-143-173, ip: [10.120.143.173]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.173"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-182" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-182"
  description  = "role: pr-c-mgt_ip_10-120-143-182, ip: [10.120.143.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-183" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-183"
  description  = "role: pr-c-mgt_ip_10-120-143-183, ip: [10.120.143.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-206" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-206"
  description  = "role: pr-c-mgt_ip_10-120-140-206, ip: [10.120.140.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-207" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-207"
  description  = "role: pr-c-mgt_ip_10-120-140-207, ip: [10.120.140.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.207"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-208" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-208"
  description  = "role: pr-c-mgt_ip_10-120-140-208, ip: [10.120.140.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-140-209" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-140-209"
  description  = "role: pr-c-mgt_ip_10-120-140-209, ip: [10.120.140.209]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.209"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-164" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-164"
  description  = "role: pr-c-mgt_ip_10-120-143-164, ip: [10.120.143.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-165" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-165"
  description  = "role: pr-c-mgt_ip_10-120-143-165, ip: [10.120.143.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-166" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-166"
  description  = "role: pr-c-mgt_ip_10-120-143-166, ip: [10.120.143.166]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.166"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-143-167" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-143-167"
  description  = "role: pr-c-mgt_ip_10-120-143-167, ip: [10.120.143.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-39-105" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-39-105"
  description  = "role: pr-c-mgt_ip_10-210-39-105, ip: [10.210.39.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.39.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-39-106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-39-106"
  description  = "role: pr-c-mgt_ip_10-210-39-106, ip: [10.210.39.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.39.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-44-25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-44-25"
  description  = "role: pr-c-mgt_ip_10-120-44-25, ip: [10.120.44.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-44-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-44-26"
  description  = "role: pr-c-mgt_ip_10-120-44-26, ip: [10.120.44.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-44-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-44-27"
  description  = "role: pr-c-mgt_ip_10-120-44-27, ip: [10.120.44.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-65-68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-65-68"
  description  = "role: pr-c-mgt_ip_10-120-65-68, ip: [10.120.65.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.65.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-65-68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-65-68"
  description  = "role: pr-c-mgt_ip_10-210-65-68, ip: [10.210.65.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.65.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-194-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-194-15"
  description  = "role: pr-c-mgt_ip_10-120-194-15, ip: [10.120.194.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-194-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-194-18"
  description  = "role: pr-c-mgt_ip_10-120-194-18, ip: [10.120.194.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-194-16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-194-16"
  description  = "role: pr-c-mgt_ip_10-120-194-16, ip: [10.120.194.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-194-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-194-17"
  description  = "role: pr-c-mgt_ip_10-120-194-17, ip: [10.120.194.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-194-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-194-11"
  description  = "role: pr-c-mgt_ip_10-120-194-11, ip: [10.120.194.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-82-166" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-82-166"
  description  = "role: pr-c-mgt_ip_10-1-82-166, ip: [10.1.82.166]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.166"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-138" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-138"
  description  = "role: pr-c-mgt_ip_10-1-83-138, ip: [10.1.83.138]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.138"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-139" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-139"
  description  = "role: pr-c-mgt_ip_10-1-83-139, ip: [10.1.83.139]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.139"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-140" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-140"
  description  = "role: pr-c-mgt_ip_10-1-83-140, ip: [10.1.83.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-78" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-78"
  description  = "role: pr-c-mgt_ip_10-1-83-78, ip: [10.1.83.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-93"
  description  = "role: pr-c-mgt_ip_10-1-83-93, ip: [10.1.83.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-118" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-118"
  description  = "role: pr-c-mgt_ip_10-1-83-118, ip: [10.1.83.118]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.118"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-38" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-38"
  description  = "role: pr-c-mgt_ip_10-1-83-38, ip: [10.1.83.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-137" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-137"
  description  = "role: pr-c-mgt_ip_10-1-83-137, ip: [10.1.83.137]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.137"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-141" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-141"
  description  = "role: pr-c-mgt_ip_10-1-83-141, ip: [10.1.83.141]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.141"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-83-142" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-83-142"
  description  = "role: pr-c-mgt_ip_10-1-83-142, ip: [10.1.83.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-18-144" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-18-144"
  description  = "role: pr-c-mgt_ip_10-1-18-144, ip: [10.1.18.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-18-183" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-18-183"
  description  = "role: pr-c-mgt_ip_10-1-18-183, ip: [10.1.18.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-18-35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-18-35"
  description  = "role: pr-c-mgt_ip_10-1-18-35, ip: [10.1.18.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-18-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-18-36"
  description  = "role: pr-c-mgt_ip_10-1-18-36, ip: [10.1.18.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-18-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-18-43"
  description  = "role: pr-c-mgt_ip_10-1-18-43, ip: [10.1.18.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-18-57" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-18-57"
  description  = "role: pr-c-mgt_ip_10-1-18-57, ip: [10.1.18.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-18-62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-18-62"
  description  = "role: pr-c-mgt_ip_10-1-18-62, ip: [10.1.18.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-18-64" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-18-64"
  description  = "role: pr-c-mgt_ip_10-1-18-64, ip: [10.1.18.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-66-144" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-66-144"
  description  = "role: pr-c-mgt_ip_10-1-66-144, ip: [10.1.66.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-66-183" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-66-183"
  description  = "role: pr-c-mgt_ip_10-1-66-183, ip: [10.1.66.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-66-35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-66-35"
  description  = "role: pr-c-mgt_ip_10-1-66-35, ip: [10.1.66.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-66-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-66-36"
  description  = "role: pr-c-mgt_ip_10-1-66-36, ip: [10.1.66.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-66-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-66-43"
  description  = "role: pr-c-mgt_ip_10-1-66-43, ip: [10.1.66.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-66-57" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-66-57"
  description  = "role: pr-c-mgt_ip_10-1-66-57, ip: [10.1.66.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-66-62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-66-62"
  description  = "role: pr-c-mgt_ip_10-1-66-62, ip: [10.1.66.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-1-66-64" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-1-66-64"
  description  = "role: pr-c-mgt_ip_10-1-66-64, ip: [10.1.66.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.66.64"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-55-13-253" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-55-13-253"
  description  = "role: pr-c-mgt_ip_10-55-13-253, ip: [10.55.13.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.13.253"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-55-13-254" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-55-13-254"
  description  = "role: pr-c-mgt_ip_10-55-13-254, ip: [10.55.13.254]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.13.254"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-55-13-255" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-55-13-255"
  description  = "role: pr-c-mgt_ip_10-55-13-255, ip: [10.55.13.255]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.13.255"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-55-14-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-55-14-18"
  description  = "role: pr-c-mgt_ip_10-55-14-18, ip: [10.55.14.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-55-14-19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-55-14-19"
  description  = "role: pr-c-mgt_ip_10-55-14-19, ip: [10.55.14.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-55-14-20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-55-14-20"
  description  = "role: pr-c-mgt_ip_10-55-14-20, ip: [10.55.14.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-55-225-253" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-55-225-253"
  description  = "role: pr-c-mgt_ip_10-55-225-253, ip: [10.55.225.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.225.253"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-55-225-254" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-55-225-254"
  description  = "role: pr-c-mgt_ip_10-55-225-254, ip: [10.55.225.254]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.225.254"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-55-225-255" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-55-225-255"
  description  = "role: pr-c-mgt_ip_10-55-225-255, ip: [10.55.225.255]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.225.255"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-55-226-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-55-226-18"
  description  = "role: pr-c-mgt_ip_10-55-226-18, ip: [10.55.226.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-55-226-19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-55-226-19"
  description  = "role: pr-c-mgt_ip_10-55-226-19, ip: [10.55.226.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-55-226-20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-55-226-20"
  description  = "role: pr-c-mgt_ip_10-55-226-20, ip: [10.55.226.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-100-9-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-100-9-11"
  description  = "role: pr-c-mgt_ip_10-100-9-11, ip: [10.100.9.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.100.9.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-100-9-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-100-9-12"
  description  = "role: pr-c-mgt_ip_10-100-9-12, ip: [10.100.9.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.100.9.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-100-9-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-100-9-13"
  description  = "role: pr-c-mgt_ip_10-100-9-13, ip: [10.100.9.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.100.9.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-100-9-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-100-9-14"
  description  = "role: pr-c-mgt_ip_10-100-9-14, ip: [10.100.9.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.100.9.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-129-11-8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-129-11-8"
  description  = "role: pr-c-mgt_ip_10-129-11-8, ip: [10.129.11.8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.11.8"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-129-11-7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-129-11-7"
  description  = "role: pr-c-mgt_ip_10-129-11-7, ip: [10.129.11.7]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.11.7"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-112-46-30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-112-46-30"
  description  = "role: pr-c-mgt_ip_10-112-46-30, ip: [10.112.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-112-46-33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-112-46-33"
  description  = "role: pr-c-mgt_ip_10-112-46-33, ip: [10.112.46.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-112-46-34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-112-46-34"
  description  = "role: pr-c-mgt_ip_10-112-46-34, ip: [10.112.46.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-46-30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-46-30"
  description  = "role: pr-c-mgt_ip_10-120-46-30, ip: [10.120.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-46-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-46-31"
  description  = "role: pr-c-mgt_ip_10-120-46-31, ip: [10.120.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-46-32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-46-32"
  description  = "role: pr-c-mgt_ip_10-120-46-32, ip: [10.120.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-46-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-46-31"
  description  = "role: pr-c-mgt_ip_10-180-46-31, ip: [10.180.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-46-32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-46-32"
  description  = "role: pr-c-mgt_ip_10-180-46-32, ip: [10.180.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-163-95" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-163-95"
  description  = "role: pr-c-mgt_ip_10-210-163-95, ip: [10.210.163.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-163-96" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-163-96"
  description  = "role: pr-c-mgt_ip_10-210-163-96, ip: [10.210.163.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-163-97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-163-97"
  description  = "role: pr-c-mgt_ip_10-210-163-97, ip: [10.210.163.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-163-98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-163-98"
  description  = "role: pr-c-mgt_ip_10-210-163-98, ip: [10.210.163.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-210-163-99" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-210-163-99"
  description  = "role: pr-c-mgt_ip_10-210-163-99, ip: [10.210.163.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-120-163-34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-120-163-34"
  description  = "role: pr-c-mgt_ip_10-120-163-34, ip: [10.120.163.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-163-211" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-163-211"
  description  = "role: pr-c-mgt_ip_10-180-163-211, ip: [10.180.163.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-163-212" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-163-212"
  description  = "role: pr-c-mgt_ip_10-180-163-212, ip: [10.180.163.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-163-213" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-163-213"
  description  = "role: pr-c-mgt_ip_10-180-163-213, ip: [10.180.163.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-163-214" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-163-214"
  description  = "role: pr-c-mgt_ip_10-180-163-214, ip: [10.180.163.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-163-218" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-163-218"
  description  = "role: pr-c-mgt_ip_10-180-163-218, ip: [10.180.163.218]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.218"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-163-102" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-163-102"
  description  = "role: pr-c-mgt_ip_10-180-163-102, ip: [10.180.163.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-163-220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-163-220"
  description  = "role: pr-c-mgt_ip_10-180-163-220, ip: [10.180.163.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-163-221" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-163-221"
  description  = "role: pr-c-mgt_ip_10-180-163-221, ip: [10.180.163.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-163-40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-163-40"
  description  = "role: pr-c-mgt_ip_10-180-163-40, ip: [10.180.163.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-141-41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-141-41"
  description  = "role: pr-c-mgt_ip_10-180-141-41, ip: [10.180.141.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.141.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-141-42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-141-42"
  description  = "role: pr-c-mgt_ip_10-180-141-42, ip: [10.180.141.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.141.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-141-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-141-43"
  description  = "role: pr-c-mgt_ip_10-180-141-43, ip: [10.180.141.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.141.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_ip_10-180-141-44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ip_10-180-141-44"
  description  = "role: pr-c-mgt_ip_10-180-141-44, ip: [10.180.141.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.141.44"]
    }
  }
}

/*======================================
#### object-groups ####
========================================*/

resource "nsxt_policy_group" "pr-c-mgt_grp_sc1-katello-prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_sc1-katello-prod"
  description  = "role: CHG0067823"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-163-130.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-136.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_stingray-mgt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_stingray-mgt"
  description  = "role: CHG0066695"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprein01.path, nsxt_policy_group.pr-c-mgt_sc1apprein02.path, nsxt_policy_group.pr-c-mgt_sc1apprein03.path, nsxt_policy_group.pr-c-mgt_sc1apprein07.path, nsxt_policy_group.pr-c-mgt_sc1apprein08.path, nsxt_policy_group.pr-c-mgt_sc1apprein09.path, nsxt_policy_group.pr-c-mgt_sc1apprein10.path, nsxt_policy_group.pr-c-mgt_sc1apprein11.path, nsxt_policy_group.pr-c-mgt_sc1apprein12.path, nsxt_policy_group.pr-c-mgt_sc1apprein13.path, nsxt_policy_group.pr-c-mgt_sc1apprein14.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_sc1-bomgar-clients" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_sc1-bomgar-clients"
  description  = "role: CHG0120371"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_scc-bgr-clt-pc1.path, nsxt_policy_group.pr-c-mgt_scc-bgr-clt-pc2.path, nsxt_policy_group.pr-c-mgt_scc-bgr-clt-pc3.path, nsxt_policy_group.pr-c-mgt_scc-bgr-clt-pc4.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_310" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_310"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_310"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_grp_aws-ddos-f5s.path, nsxt_policy_group.pr-c-mgt_grp_aws-f5s.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_inv-pr-stingray-subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_inv-pr-stingray-subnets"
  description  = "role: CHG0067823, CHG0071650"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_inv-cde-int-pres-lan.path, nsxt_policy_group.pr-c-mgt_inv-cde-api-lan.path, nsxt_policy_group.pr-c-mgt_inv-cde-ext-pres-lan.path, nsxt_policy_group.pr-c-mgt_inv-fe-tier.path, nsxt_policy_group.pr-c-mgt_inv-cde-lan01.path, nsxt_policy_group.pr-c-mgt_inv-ncde-lan01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_qlickview_app" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_qlickview_app"
  description  = "role: pr-c-mgt_grp_qlickview_app"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnprncp005.path, nsxt_policy_group.pr-c-mgt_sc1wnprncp005-vmc.path, nsxt_policy_group.pr-c-mgt_sc1wnprncp006.path, nsxt_policy_group.pr-c-mgt_sc1wnprncp006-vmc.path, nsxt_policy_group.pr-c-mgt_ip_10-120-99-23.path, nsxt_policy_group.pr-c-mgt_ip_10-120-99-24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_qlickview_web" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_qlickview_web"
  description  = "role: pr-c-mgt_grp_qlickview_web"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-66-92.path, nsxt_policy_group.pr-c-mgt_ip_10-120-66-93.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_vsphere_mgmt_nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_vsphere_mgmt_nets"
  description  = "role: pr-c-mgt_grp_vsphere_mgmt_nets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_brs.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_scc.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_gib.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_sof.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_dat.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_pp.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_stj.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_kra.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_ld6.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_man.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_hci_stj.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_brs_hci.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_mal.path, nsxt_policy_group.pr-c-mgt_us-nj-10-174-104-0.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_nj2.path, nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_us-in1.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-scc-bomgar-jumphosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-scc-bomgar-jumphosts"
  description  = "role: CHG0114077"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnprcmg41-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg42-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg43-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg44-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1uxprcmg31-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1uxprcmg32-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1uxprcmg33-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1uxprcmg34-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-bomgar-appliances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-bomgar-appliances"
  description  = "role: CHG0114077"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_grp_grp-brs-bomgar-appliances.path, nsxt_policy_group.pr-c-mgt_grp_grp-sc1-bomgar-appliances.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_device-management-networks" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_device-management-networks"
  description  = "role: pr-c-mgt_grp_device-management-networks"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-99-254-0slash24.path, nsxt_policy_group.pr-c-mgt_10-55-99-0slash24.path, nsxt_policy_group.pr-c-mgt_10-56-99-0slash24.path, nsxt_policy_group.pr-c-mgt_10-99-253-0slash24.path, nsxt_policy_group.pr-c-mgt_10-112-129-0slash24.path, nsxt_policy_group.pr-c-mgt_ip_10-180-129-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-129-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-210-129-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-1-99-0s24.path, nsxt_policy_group.pr-c-mgt_ip_192-168-1-0s24.path, nsxt_policy_group.pr-c-mgt_ip_192-168-10-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-211-129-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-212-129-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-213-129-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-214-129-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-215-129-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-216-129-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_rds-servers-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_rds-servers-scc"
  description  = "role: pr-c-mgt_grp_rds-servers-scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-141-41.path, nsxt_policy_group.pr-c-mgt_ip_10-120-141-42.path, nsxt_policy_group.pr-c-mgt_ip_10-120-141-43.path, nsxt_policy_group.pr-c-mgt_ip_10-120-141-44.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_skybox-appliances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_skybox-appliances"
  description  = "role: CHG0121057"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1appresc02-ilo.path, nsxt_policy_group.pr-c-mgt_sc1appresc03-ilo.path, nsxt_policy_group.pr-c-mgt_sc1appresc02-data.path, nsxt_policy_group.pr-c-mgt_sc1appresc03-data.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_bomgar_asdm_access_brs_gib" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_bomgar_asdm_access_brs_gib"
  description  = "role: pr-c-mgt_grp_bomgar_asdm_access_brs_gib"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-210-129-220.path, nsxt_policy_group.pr-c-mgt_ip_10-210-129-70.path, nsxt_policy_group.pr-c-mgt_ip_10-210-129-52.path, nsxt_policy_group.pr-c-mgt_ip_10-210-129-250.path, nsxt_policy_group.pr-c-mgt_ip_10-180-129-250.path, nsxt_policy_group.pr-c-mgt_ip_10-180-129-52.path, nsxt_policy_group.pr-c-mgt_ip_10-180-129-220.path, nsxt_policy_group.pr-c-mgt_ip_10-180-129-221.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_cde-ilo-range" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_cde-ilo-range"
  description  = "role: CHG0122059"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-112-10-0slash23.path, nsxt_policy_group.pr-c-mgt_10-120-130-0slash24.path, nsxt_policy_group.pr-c-mgt_10-120-80-0slash24.path, nsxt_policy_group.pr-c-mgt_10-180-130-0slash24.path, nsxt_policy_group.pr-c-mgt_10-180-80-0slash24.path, nsxt_policy_group.pr-c-mgt_10-201-254-0slash24.path, nsxt_policy_group.pr-c-mgt_10-210-230-0slash24.path, nsxt_policy_group.pr-c-mgt_10-100-254-0slash24.path, nsxt_policy_group.pr-c-mgt_10-123-200-0slash24.path, nsxt_policy_group.pr-c-mgt_10-210-8-0slash24.path, nsxt_policy_group.pr-c-mgt_10-53-100-0slash24.path, nsxt_policy_group.pr-c-mgt_10-54-98-0slash24.path, nsxt_policy_group.pr-c-mgt_10-55-8-0slash24.path, nsxt_policy_group.pr-c-mgt_10-8-2-0slash24.path, nsxt_policy_group.pr-c-mgt_10-56-8-0slash24.path, nsxt_policy_group.pr-c-mgt_10-201-225-0slash24.path, nsxt_policy_group.pr-c-mgt_10-129-10-0slash23.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_oneview" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_oneview"
  description  = "role: pr-c-mgt_grp_oneview"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brsuxpremg25.path, nsxt_policy_group.pr-c-mgt_gibuxpremg25.path, nsxt_policy_group.pr-c-mgt_ld6uxpremg01.path, nsxt_policy_group.pr-c-mgt_sc1uxpremg26.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_checkpoint-mds-cmas" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_checkpoint-mds-cmas"
  description  = "role: pr-c-mgt_grp_checkpoint-mds-cmas"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_grp_gib-smart-1.path, nsxt_policy_group.pr-c-mgt_grp_scc-smart-1.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-cx-cde-jump-hosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-cx-cde-jump-hosts"
  description  = "role: CHG0070755"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnprcmg01-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg02-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_295" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_295"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_295"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-125-0-0s22.path, nsxt_policy_group.pr-c-mgt_10-125-16-0s22.path, nsxt_policy_group.pr-c-mgt_ip_10-125-4-0s22.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_300" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_300"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_300"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-120-141-41.path, nsxt_policy_group.pr-c-mgt_10-120-141-42.path, nsxt_policy_group.pr-c-mgt_10-120-141-43.path, nsxt_policy_group.pr-c-mgt_10-120-141-44.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_304" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_304"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_304"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-120-141-41.path, nsxt_policy_group.pr-c-mgt_10-120-141-42.path, nsxt_policy_group.pr-c-mgt_10-120-141-43.path, nsxt_policy_group.pr-c-mgt_10-120-141-44.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_306" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_306"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_306"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-125-20-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-125-4-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-125-8-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_317" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_317"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_317"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_mscuxpremn001.path, nsxt_policy_group.pr-c-mgt_mscuxpremn002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_aws-supernets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_aws-supernets"
  description  = "role: pr-c-mgt_grp_aws-supernets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_aws-supernet-eu.path, nsxt_policy_group.pr-c-mgt_aws-supernet-us.path, nsxt_policy_group.pr-c-mgt_aws-supernet-us2.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_26"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_26"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnprcmg41-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg42-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg43-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg44-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_29"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_29"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1bigiq04-mgmt-prod-williamhill.path, nsxt_policy_group.pr-c-mgt_sc1wfprein003.path, nsxt_policy_group.pr-c-mgt_sc1wfprein004.path, nsxt_policy_group.pr-c-mgt_sc1wfprein005.path, nsxt_policy_group.pr-c-mgt_scc-f5-1-mgmt.path, nsxt_policy_group.pr-c-mgt_scc-f5-2-mgmt.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_36"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_36"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnprcmg41-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg42-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg43-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg44-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_aws-dcs-ire-nva" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_aws-dcs-ire-nva"
  description  = "role: CHG0140344"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_irewnprdc01.path, nsxt_policy_group.pr-c-mgt_irewnprdc02.path, nsxt_policy_group.pr-c-mgt_nvawnprdc01.path, nsxt_policy_group.pr-c-mgt_nvawnprdc02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_39"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_39"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnprcmg41-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg42-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg43-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg44-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_40"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_40"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_aws-ddos-np1-100-78-48-0s24.path, nsxt_policy_group.pr-c-mgt_aws-ddos-np1-100-78-49-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_51"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_51"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnprcmg41-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg42-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg43-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg44-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_71" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_71"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_71"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_aws-ddos-np1-100-78-48-0s24.path, nsxt_policy_group.pr-c-mgt_aws-ddos-np1-100-78-49-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_55"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_55"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_vmc-sc1-non-whc-prod.path, nsxt_policy_group.pr-c-mgt_vmc-sc1-oracle-prod.path, nsxt_policy_group.pr-c-mgt_vmc-sc1-whc-prod.path, nsxt_policy_group.pr-c-mgt_vmc-whc-dev.path, nsxt_policy_group.pr-c-mgt_vmc-whc-pp-10-126-188-0_22.path, nsxt_policy_group.pr-c-mgt_ip_10-126-44-0s22.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_53"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_53"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnprcmg41-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg42-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg43-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg44-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_57" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_57"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_57"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnprcmg41-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg42-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg43-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg44-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_58" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_58"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_58"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brs-xiv-array-1.path, nsxt_policy_group.pr-c-mgt_brs-xiv-array-2.path, nsxt_policy_group.pr-c-mgt_brs-xiv_array-3.path, nsxt_policy_group.pr-c-mgt_scc-xiv-array-1.path, nsxt_policy_group.pr-c-mgt_scc-xiv-array-2.path, nsxt_policy_group.pr-c-mgt_scc-xiv-array-3.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-bomgar-grp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-bomgar-grp"
  description  = "role: pr-c-mgt_grp_scc-bomgar-grp"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-120-141-42.path, nsxt_policy_group.pr-c-mgt_10-120-141-43.path, nsxt_policy_group.pr-c-mgt_10-120-141-44.path, nsxt_policy_group.pr-c-mgt_ip_10-120-141-41.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_69" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_69"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_69"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_service-mgmt-scc-whc-prod-sddc.path, nsxt_policy_group.pr-c-mgt_ip_10-156-4-0s25.path, nsxt_policy_group.pr-c-mgt_ip_10-156-4-128s25.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_aws-ddos-f5s" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_aws-ddos-f5s"
  description  = "role: CHG0126802"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-125-0-181.path, nsxt_policy_group.pr-c-mgt_10-125-0-182.path, nsxt_policy_group.pr-c-mgt_10-125-0-198.path, nsxt_policy_group.pr-c-mgt_10-125-0-227.path, nsxt_policy_group.pr-c-mgt_10-125-0-246.path, nsxt_policy_group.pr-c-mgt_10-125-0-36.path, nsxt_policy_group.pr-c-mgt_10-125-0-56.path, nsxt_policy_group.pr-c-mgt_10-125-0-6.path, nsxt_policy_group.pr-c-mgt_10-125-0-87.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_aws-f5s" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_aws-f5s"
  description  = "role: CHG0128017"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-125-0-106.path, nsxt_policy_group.pr-c-mgt_10-125-0-27.path, nsxt_policy_group.pr-c-mgt_10-125-16-205.path, nsxt_policy_group.pr-c-mgt_10-125-16-216.path, nsxt_policy_group.pr-c-mgt_10-125-16-36.path, nsxt_policy_group.pr-c-mgt_10-125-16-90.path, nsxt_policy_group.pr-c-mgt_10-125-4-107.path, nsxt_policy_group.pr-c-mgt_10-125-4-198.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-brs-bomgar-appliances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-brs-bomgar-appliances"
  description  = "role: CHG0114418"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brsapprcsc51-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_brsjump-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_brsapprcsc52-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-sc1-bomgar-appliances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-sc1-bomgar-appliances"
  description  = "role: CHG0114418"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprcsc50-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1apprcsc51-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1jump-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_gib-smart-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_gib-smart-1"
  description  = "role: pr-c-mgt_grp_gib-smart-1"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_can-dr-ext-cma2.path, nsxt_policy_group.pr-c-mgt_gi-mpl-fm01.path, nsxt_policy_group.pr-c-mgt_gib-pr-ext-cma2.path, nsxt_policy_group.pr-c-mgt_brs-dr-ext-cma2.path, nsxt_policy_group.pr-c-mgt_brs-pp-ext-cma2.path, nsxt_policy_group.pr-c-mgt_scc-pr-ext-cma2.path, nsxt_policy_group.pr-c-mgt_stj-cp-ext-cma2.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-smart-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-smart-1"
  description  = "role: pr-c-mgt_grp_scc-smart-1"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_can-dr-ext-cma1.path, nsxt_policy_group.pr-c-mgt_gib-pr-ext-cma1.path, nsxt_policy_group.pr-c-mgt_uk-scc-fm01.path, nsxt_policy_group.pr-c-mgt_brs-dr-ext-cma1.path, nsxt_policy_group.pr-c-mgt_brs-pp-ext-cma1.path, nsxt_policy_group.pr-c-mgt_scc-pr-ext-cma1.path, nsxt_policy_group.pr-c-mgt_stj-cp-ext-cma1.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-c-layer7-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-c-layer7-servers"
  description  = "role: pr-c-mgt_grp_grp-pr-c-layer7-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprcwb017.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb018.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb019.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb020.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb021.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb022.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb023.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb024.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb013.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb014.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb015.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb016.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-181.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-182.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-183.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-184.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-moni-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-moni-servers"
  description  = "role: pr-c-mgt_grp_scc-moni-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1-ux-pre-mn13.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-31.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-32.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-33.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-35.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-36.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-layer7new-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-layer7new-servers"
  description  = "role: pr-c-mgt_grp_grp-pr-layer7new-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprcwb005.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb006.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb007.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb008.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_117" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_117"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_117"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprcwb11.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb008.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb017.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb018.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb019.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb020.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb021.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb022.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb023.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb024.path, nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-layer7-servers.path, nsxt_policy_group.pr-c-mgt_grp_grp-pr-layer7new-servers.path, nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-layer7-mgmt-3.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_ob-web-app-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_ob-web-app-servers"
  description  = "role: pr-c-mgt_grp_ob-web-app-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprcap31.path, nsxt_policy_group.pr-c-mgt_sc1uxprcap32.path, nsxt_policy_group.pr-c-mgt_sc1uxprcap45.path, nsxt_policy_group.pr-c-mgt_sc1uxprcap46.path, nsxt_policy_group.pr-c-mgt_sc1uxprcwb41.path, nsxt_policy_group.pr-c-mgt_sc1uxprcwb42.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb005.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb006.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb007.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb008.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb03.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb04.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb017.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb018.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb019.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb020.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb021.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb022.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb023.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb024.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-181.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-182.path, nsxt_policy_group.pr-c-mgt_ip_10-120-137-11.path, nsxt_policy_group.pr-c-mgt_ip_10-120-137-12.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_67" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_67"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_67"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-163-134.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-135.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-c-layer7-mgmt-3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-c-layer7-mgmt-3"
  description  = "role: pr-c-mgt_grp_grp-pr-c-layer7-mgmt-3"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-131-200.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-201.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-202.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-203.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-204.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-205.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-206.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-207.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_83"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_83"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-163-134.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-135.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_298" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_298"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_298"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprcap31.path, nsxt_policy_group.pr-c-mgt_sc1uxprcap32.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_289" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_289"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_289"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brs-nms-win.path, nsxt_policy_group.pr-c-mgt_sc1-cacti.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_f5-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_f5-mgmt"
  description  = "role: pr-c-mgt_grp_f5-mgmt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wfprein003.path, nsxt_policy_group.pr-c-mgt_sc1wfprein004.path, nsxt_policy_group.pr-c-mgt_sc1wfprein005.path, nsxt_policy_group.pr-c-mgt_sc1bigiq04-mgmt-prod-williamhill.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-12.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-f5-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-f5-mgmt"
  description  = "role: pr-c-mgt_grp_scc-f5-mgmt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_scc-f5-1-mgmt.path, nsxt_policy_group.pr-c-mgt_scc-f5-2-mgmt.path, nsxt_policy_group.pr-c-mgt_sc1wfprein003.path, nsxt_policy_group.pr-c-mgt_sc1wfprein004.path, nsxt_policy_group.pr-c-mgt_sc1wfprein005.path, nsxt_policy_group.pr-c-mgt_sc1bigiq04-mgmt-prod-williamhill.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_f5-splunk-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_f5-splunk-servers"
  description  = "role: pr-c-mgt_grp_f5-splunk-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpremn001.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn77.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_stingray-group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_stingray-group"
  description  = "role: CHG0074843 - sc1apprein04 to 09"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprein12.path, nsxt_policy_group.pr-c-mgt_sc1apprein13.path, nsxt_policy_group.pr-c-mgt_sc1apprein10.path, nsxt_policy_group.pr-c-mgt_sc1apprein11.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-200.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-201.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-202.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-203.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-204.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-205.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_235" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_235"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_235"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpremn74.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn77.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn79.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_27"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_27"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-180-163-140.path, nsxt_policy_group.pr-c-mgt_ip_10-180-163-145.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_stingray_prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_stingray_prod"
  description  = "role: CHG0066695"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprein07.path, nsxt_policy_group.pr-c-mgt_sc1apprein08.path, nsxt_policy_group.pr-c-mgt_sc1apprein09.path, nsxt_policy_group.pr-c-mgt_sc1apprein10.path, nsxt_policy_group.pr-c-mgt_sc1apprein11.path, nsxt_policy_group.pr-c-mgt_sc1apprein12.path, nsxt_policy_group.pr-c-mgt_sc1apprein13.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-200.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-201.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-202.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-ldap-group-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-ldap-group-scc"
  description  = "role: pr-c-mgt_grp_grp-ldap-group-scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-194-12.path, nsxt_policy_group.pr-c-mgt_ip_10-120-194-13.path, nsxt_policy_group.pr-c-mgt_ip_10-120-194-14.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_wh-f5-devices" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_wh-f5-devices"
  description  = "role: pr-c-mgt_grp_wh-f5-devices"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-180-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-180-140-12.path, nsxt_policy_group.pr-c-mgt_ip_10-180-140-13.path, nsxt_policy_group.pr-c-mgt_ip_10-180-140-14.path, nsxt_policy_group.pr-c-mgt_ip_10-180-140-15.path, nsxt_policy_group.pr-c-mgt_ip_10-180-140-16.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-12.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-13.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-14.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-15.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-16.path, nsxt_policy_group.pr-c-mgt_ip_10-210-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-210-140-12.path, nsxt_policy_group.pr-c-mgt_ip_10-211-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-212-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-213-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-214-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-215-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-216-140-11.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_292" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_292"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_292"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-129-151.path, nsxt_policy_group.pr-c-mgt_ip_10-180-129-151.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_clp-heavyforwarders" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_clp-heavyforwarders"
  description  = "role: pr-c-mgt_grp_clp-heavyforwarders"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_prdxclp25fwd001.path, nsxt_policy_group.pr-c-mgt_prdxclp25fwd002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_278" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_278"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_278"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_aws-ddos-big-ip-net.path, nsxt_policy_group.pr-c-mgt_aws-us-ddos-big-ip-net.path, nsxt_policy_group.pr-c-mgt_aws-irl-ddos-big-ip-net.path, nsxt_policy_group.pr-c-mgt_aws-ddos-orp-ext.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_9"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_9"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_aws-ddos-orp-ext.path, nsxt_policy_group.pr-c-mgt_aws-us-ddos-big-ip-net.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_321" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_321"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_321"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_aws-ddos-np1-100-78-48-0s24.path, nsxt_policy_group.pr-c-mgt_aws-ddos-np1-100-78-49-0s24.path, nsxt_policy_group.pr-c-mgt_aws-ddos-np1-100-78-50-0s24.path, nsxt_policy_group.pr-c-mgt_aws-ddos-pt1-bigip-net.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_njp-dev-ddos-subnet" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_njp-dev-ddos-subnet"
  description  = "role: CHG0125909"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-125-20-0slash22.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_45"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_45"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprein01.path, nsxt_policy_group.pr-c-mgt_sc1apprein02.path, nsxt_policy_group.pr-c-mgt_sc1apprein07.path, nsxt_policy_group.pr-c-mgt_sc1apprein08.path, nsxt_policy_group.pr-c-mgt_sc1apprein09.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_8"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_8"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_svr-sc1wnprrto01-mgmt-re.path, nsxt_policy_group.pr-c-mgt_svr-sc1wnprrto02-mgmt-re.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_cp-vpn-cde-mgmt-nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_cp-vpn-cde-mgmt-nets"
  description  = "role: pr-c-mgt_grp_cp-vpn-cde-mgmt-nets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-80-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-130-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_ilo-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_ilo-access"
  description  = "role: pr-c-mgt_grp_ilo-access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path, nsxt_policy_group.pr-c-mgt_serveroperations-27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_hp-ilo-subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_hp-ilo-subnets"
  description  = "role: pr-c-mgt_grp_hp-ilo-subnets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-130-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-80-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-commvault-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-commvault-servers"
  description  = "role: CHG0140759"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brsuxprbkms01.path, nsxt_policy_group.pr-c-mgt_brsuxprbkms02.path, nsxt_policy_group.pr-c-mgt_brsuxprbkms03.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_networkteam-vpn-range" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_networkteam-vpn-range"
  description  = "role: CHG0123928"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_192-168-3-208slash28.path, nsxt_policy_group.pr-c-mgt_192-168-3-2slash27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_cde-direct-access-nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_cde-direct-access-nets"
  description  = "role: group for direct access certain networks in CDE"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_bladelogic-dmz-network-24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-129-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-130-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-134-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-139-224s27.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-141-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-160s27.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-64s27.path, nsxt_policy_group.pr-c-mgt_ip_10-120-80-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_tufincollectors" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_tufincollectors"
  description  = "role: pr-c-mgt_grp_tufincollectors"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpremg005-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_tufiniosdevices" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_tufiniosdevices"
  description  = "role: pr-c-mgt_grp_tufiniosdevices"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_uk-sc1-cr01.path, nsxt_policy_group.pr-c-mgt_uk-sc1-cr02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_149" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_149"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_149"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-180-163-48.path, nsxt_policy_group.pr-c-mgt_grp_tufincollectors.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_tufincheckpointmds" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_tufincheckpointmds"
  description  = "role: pr-c-mgt_grp_tufincheckpointmds"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_gi-mpl-fm01.path, nsxt_policy_group.pr-c-mgt_uk-scc-fm01.path, nsxt_policy_group.pr-c-mgt_grp_scc-smart-1.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_54"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_54"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_scc-pr-ext-cma1.path, nsxt_policy_group.pr-c-mgt_grp_scc-smart-1.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_225" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_225"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_225"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_server-ilo-network-24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-80-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_211" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_211"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_211"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1-wn-pre-mg01.path, nsxt_policy_group.pr-c-mgt_ip_10-110-163-30.path, nsxt_policy_group.pr-c-mgt_ip_10-180-139-210.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-30.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_323" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_323"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_323"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-131-41.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-42.path, nsxt_policy_group.pr-c-mgt_ip_10-120-132-31.path, nsxt_policy_group.pr-c-mgt_ip_10-120-132-45.path, nsxt_policy_group.pr-c-mgt_ip_10-120-132-46.path, nsxt_policy_group.pr-c-mgt_ip_10-120-137-11.path, nsxt_policy_group.pr-c-mgt_ip_10-120-137-12.path, nsxt_policy_group.pr-c-mgt_ip_10-120-132-32.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_173" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_173"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_173"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_uk-sc1-network-mgmt-24.path, nsxt_policy_group.pr-c-mgt_server-ilo-network-24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_293" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_293"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_293"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_scc-f5-1-mgmt.path, nsxt_policy_group.pr-c-mgt_grp_scc-f5-mgmt.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_rfc-1918" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_rfc-1918"
  description  = "role: CHG0014159"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_172-16-0-0s12.path, nsxt_policy_group.pr-c-mgt_ip_192-168-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-0-0-0s8.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_43"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_43"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnpremg10.path, nsxt_policy_group.pr-c-mgt_sc1wnpremg11.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_athene-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_athene-servers"
  description  = "role: pr-c-mgt_grp_athene-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnpremn20a.path, nsxt_policy_group.pr-c-mgt_sc1wnpremn21a.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_287" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_287"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_287"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1prapvc01.path, nsxt_policy_group.pr-c-mgt_sc1wnprevc01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-c-nms-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-c-nms-mgmt"
  description  = "role: pr-c-mgt_grp_grp-pr-c-nms-mgmt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_scc-nms-man.path, nsxt_policy_group.pr-c-mgt_sc1-cacti.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-131.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_104" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_104"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_104"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_stjwnats.path, nsxt_policy_group.pr-c-mgt_ip_10-120-194-0s26.path, nsxt_policy_group.pr-c-mgt_ip_10-120-242-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_110" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_110"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_110"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-ad-child.path, nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-ad-parent.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_116" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_116"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_116"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_bladelogic-dmz-network-24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-146-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_215" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_215"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_215"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_gib-storage-subnet.path, nsxt_policy_group.pr-c-mgt_ld6-san-switches.path, nsxt_policy_group.pr-c-mgt_grp_rfc-1918.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_hp-irs-server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_hp-irs-server"
  description  = "role: pr-c-mgt_grp_hp-irs-server"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnpremn01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_hp-irs-destinations" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_hp-irs-destinations"
  description  = "role: pr-c-mgt_grp_hp-irs-destinations"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-130-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-134-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-80-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-gib-whapi-portal-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-gib-whapi-portal-servers"
  description  = "role: pr-c-mgt_grp_grp-gib-whapi-portal-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_gibux181.path, nsxt_policy_group.pr-c-mgt_gibux191.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_1"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_1"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_netsec-27.path, nsxt_policy_group.pr-c-mgt_infosec-28.path, nsxt_policy_group.pr-c-mgt_netsec-oncall-28.path, nsxt_policy_group.pr-c-mgt_serveroperations-27.path, nsxt_policy_group.pr-c-mgt_lcw-stuarthenshaw.path, nsxt_policy_group.pr-c-mgt_lcw-craigtate.path, nsxt_policy_group.pr-c-mgt_brs-fwab-mgmt-nat.path, nsxt_policy_group.pr-c-mgt_net_10-55-60-0_28.path, nsxt_policy_group.pr-c-mgt_grp_stj-networksteam.path, nsxt_policy_group.pr-c-mgt_grp_tss-aws-net.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_whapi-gateway-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_whapi-gateway-access"
  description  = "role: pr-c-mgt_grp_whapi-gateway-access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_host-10-180-19-180.path, nsxt_policy_group.pr-c-mgt_gib-alejandrogalindo2.path, nsxt_policy_group.pr-c-mgt_host-10-180-18-126.path, nsxt_policy_group.pr-c-mgt_brsuxprein02.path, nsxt_policy_group.pr-c-mgt_net-10-17-100-0-slash25.path, nsxt_policy_group.pr-c-mgt_host-10-180-19-248.path, nsxt_policy_group.pr-c-mgt_who-karolstatkiewicz.path, nsxt_policy_group.pr-c-mgt_gib-alejandrogalindo1.path, nsxt_policy_group.pr-c-mgt_host-10-180-18-76.path, nsxt_policy_group.pr-c-mgt_host-10-180-19-97.path, nsxt_policy_group.pr-c-mgt_host-10-180-20-189.path, nsxt_policy_group.pr-c-mgt_host-10-1-86-37.path, nsxt_policy_group.pr-c-mgt_host-10-1-87-34.path, nsxt_policy_group.pr-c-mgt_host-10-1-29-37.path, nsxt_policy_group.pr-c-mgt_host-10-17-8-37.path, nsxt_policy_group.pr-c-mgt_host-10-180-19-205.path, nsxt_policy_group.pr-c-mgt_host-10-180-18-100.path, nsxt_policy_group.pr-c-mgt_host-10-180-19-145.path, nsxt_policy_group.pr-c-mgt_who-neilbellamy.path, nsxt_policy_group.pr-c-mgt_10-1-78-37.path, nsxt_policy_group.pr-c-mgt_gib-catalinmerluscalap.path, nsxt_policy_group.pr-c-mgt_gib-carlospimentel.path, nsxt_policy_group.pr-c-mgt_who-neil-bellamy.path, nsxt_policy_group.pr-c-mgt_lcw-vincebaker.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_whapi-gateway-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_whapi-gateway-servers"
  description  = "role: pr-c-mgt_grp_whapi-gateway-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprcmg01.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb017.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb018.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb019.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb020.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb021.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb022.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb023.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb024.path, nsxt_policy_group.pr-c-mgt_grp_scc-layer7-gateway.path, nsxt_policy_group.pr-c-mgt_grp_grp-pr-layer7new-servers.path, nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-layer7-mgmt-3.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_191" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_191"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_191"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_gibux181.path, nsxt_policy_group.pr-c-mgt_gibux182.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_192" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_192"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_192"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprcwb01.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb02.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb03.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb04.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb017.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb018.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb019.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb020.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb021.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb022.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb023.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb024.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_15"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_15"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_citywalk-23.path, nsxt_policy_group.pr-c-mgt_net_10-55-60-0_28.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_network_services_team" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_network_services_team"
  description  = "role: CHG0015230"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_netsec-27.path, nsxt_policy_group.pr-c-mgt_infosec-28.path, nsxt_policy_group.pr-c-mgt_netsec-oncall-28.path, nsxt_policy_group.pr-c-mgt_net_10-55-60-0_28.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_48"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_48"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1-ncs1.path, nsxt_policy_group.pr-c-mgt_sc1-ncs2.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_47"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_47"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_netsec-27.path, nsxt_policy_group.pr-c-mgt_infosec-28.path, nsxt_policy_group.pr-c-mgt_netsec-oncall-28.path, nsxt_policy_group.pr-c-mgt_service_desk_team.path, nsxt_policy_group.pr-c-mgt_serveroperations-27.path, nsxt_policy_group.pr-c-mgt_stj-trading-ia-range.path, nsxt_policy_group.pr-c-mgt_lsj-monitoringpc2.path, nsxt_policy_group.pr-c-mgt_stj-grahameades.path, nsxt_policy_group.pr-c-mgt_nev-bryanmarek.path, nsxt_policy_group.pr-c-mgt_net_10-55-60-0_28.path, nsxt_policy_group.pr-c-mgt_ip_10-1-82-220.path, nsxt_policy_group.pr-c-mgt_ip_10-1-22-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-1-82-128s27.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-0s29.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-64s27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_stingray-mgt-tcp-9070-9090-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_stingray-mgt-tcp-9070-9090-access"
  description  = "role: pr-c-mgt_grp_stingray-mgt-tcp-9070-9090-access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_serveroperations-27.path, nsxt_policy_group.pr-c-mgt_who-carlosmendez.path, nsxt_policy_group.pr-c-mgt_who-dandoyle.path, nsxt_policy_group.pr-c-mgt_who-danesquival.path, nsxt_policy_group.pr-c-mgt_who-edwardlynn.path, nsxt_policy_group.pr-c-mgt_who-ericheichinger.path, nsxt_policy_group.pr-c-mgt_who-gorkamolero.path, nsxt_policy_group.pr-c-mgt_who-istvanpapp.path, nsxt_policy_group.pr-c-mgt_who-jamesmoody.path, nsxt_policy_group.pr-c-mgt_who-josetalens.path, nsxt_policy_group.pr-c-mgt_who-martinkuegler.path, nsxt_policy_group.pr-c-mgt_who-michaeldally.path, nsxt_policy_group.pr-c-mgt_who-michalhorzela.path, nsxt_policy_group.pr-c-mgt_who-patrickdiloreto.path, nsxt_policy_group.pr-c-mgt_who-pedrogutierrez.path, nsxt_policy_group.pr-c-mgt_who-thomasmodeneis.path, nsxt_policy_group.pr-c-mgt_lcw-jennyfarrell.path, nsxt_policy_group.pr-c-mgt_lcw-robrussell.path, nsxt_policy_group.pr-c-mgt_lcw-stevehammersley.path, nsxt_policy_group.pr-c-mgt_lcw-steveibbotson.path, nsxt_policy_group.pr-c-mgt_lcw-andrewdonachie.path, nsxt_policy_group.pr-c-mgt_lcw-chriswren.path, nsxt_policy_group.pr-c-mgt_lcw-danferry.path, nsxt_policy_group.pr-c-mgt_lcw-davidbarszczak.path, nsxt_policy_group.pr-c-mgt_lcw-garethsephton.path, nsxt_policy_group.pr-c-mgt_lcw-markpetrie.path, nsxt_policy_group.pr-c-mgt_lcw-ravisingh.path, nsxt_policy_group.pr-c-mgt_lcw-richardscott.path, nsxt_policy_group.pr-c-mgt_lcw-roblewis.path, nsxt_policy_group.pr-c-mgt_lcw-stevewilson.path, nsxt_policy_group.pr-c-mgt_lcw-tomfield.path, nsxt_policy_group.pr-c-mgt_stj-alastairmontgomery.path, nsxt_policy_group.pr-c-mgt_stj-joncandlin.path, nsxt_policy_group.pr-c-mgt_who-marcuscampbell2.path, nsxt_policy_group.pr-c-mgt_who-neilbellamy.path, nsxt_policy_group.pr-c-mgt_who-vincentpalmer.path, nsxt_policy_group.pr-c-mgt_who-vincentpalmer2.path, nsxt_policy_group.pr-c-mgt_who-marcuscampbell.path, nsxt_policy_group.pr-c-mgt_usr-wpp-agalindo.path, nsxt_policy_group.pr-c-mgt_usr-wpp-agalindo2.path, nsxt_policy_group.pr-c-mgt_usr-lcw-nchrzanowski.path, nsxt_policy_group.pr-c-mgt_stj-grahameades.path, nsxt_policy_group.pr-c-mgt_lcw-gaganthakur.path, nsxt_policy_group.pr-c-mgt_lcw-richardgarforth.path, nsxt_policy_group.pr-c-mgt_stj-mikebest.path, nsxt_policy_group.pr-c-mgt_gib-connor.path, nsxt_policy_group.pr-c-mgt_10-55-1-190.path, nsxt_policy_group.pr-c-mgt_krk-aleksanderjarek.path, nsxt_policy_group.pr-c-mgt_krk-bartoszmarona.path, nsxt_policy_group.pr-c-mgt_krk-bartoszopila.path, nsxt_policy_group.pr-c-mgt_krk-jakubswider.path, nsxt_policy_group.pr-c-mgt_krk-kamiljasko.path, nsxt_policy_group.pr-c-mgt_krk-luciansilva.path, nsxt_policy_group.pr-c-mgt_krk-lukaszziemba.path, nsxt_policy_group.pr-c-mgt_krk-maciejwolk.path, nsxt_policy_group.pr-c-mgt_krk-pawelskarbinski.path, nsxt_policy_group.pr-c-mgt_krk-piotrkalinski.path, nsxt_policy_group.pr-c-mgt_krk-piotrkapica.path, nsxt_policy_group.pr-c-mgt_krk-raulacedo.path, nsxt_policy_group.pr-c-mgt_krk-robertscislowicz.path, nsxt_policy_group.pr-c-mgt_desktop-c0reen2-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_krk-eoc_team.path, nsxt_policy_group.pr-c-mgt_krk-eoc_team-wifi.path, nsxt_policy_group.pr-c-mgt_krk-pawel_skarbinski.path, nsxt_policy_group.pr-c-mgt_10-1-74-72.path, nsxt_policy_group.pr-c-mgt_ip_10-1-112-230.path, nsxt_policy_group.pr-c-mgt_ip_10-1-21-118.path, nsxt_policy_group.pr-c-mgt_ip_10-1-22-17.path, nsxt_policy_group.pr-c-mgt_ip_10-1-22-181.path, nsxt_policy_group.pr-c-mgt_ip_10-1-22-185.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-15.path, nsxt_policy_group.pr-c-mgt_ip_10-1-22-33.path, nsxt_policy_group.pr-c-mgt_grp_systemengineers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_gib-checkpoint" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_gib-checkpoint"
  description  = "role: pr-c-mgt_grp_gib-checkpoint"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-180-129-69.path, nsxt_policy_group.pr-c-mgt_ip_10-180-129-70.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_birstall_checkpointfirewalls" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_birstall_checkpointfirewalls"
  description  = "role: CHG0039249"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_birstall-fwa.path, nsxt_policy_group.pr-c-mgt_birstall-fwb.path, nsxt_policy_group.pr-c-mgt_brs-test-global-fw01.path, nsxt_policy_group.pr-c-mgt_birstall-fwb-new.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_35"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_35"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brs-dr-ext-cma1.path, nsxt_policy_group.pr-c-mgt_brs-test-global-cma1.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_222" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_222"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_222"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brs-dr-ext-cma1.path, nsxt_policy_group.pr-c-mgt_uk-scc-fm01.path, nsxt_policy_group.pr-c-mgt_brs-lab-ext-cma1.path, nsxt_policy_group.pr-c-mgt_brs-lab-ext-cma2.path, nsxt_policy_group.pr-c-mgt_brs-test-global-cma1.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_brs-checkpoint-firewalls" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_brs-checkpoint-firewalls"
  description  = "role: pr-c-mgt_grp_brs-checkpoint-firewalls"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-210-129-241.path, nsxt_policy_group.pr-c-mgt_10-210-129-242.path, nsxt_policy_group.pr-c-mgt_10-210-129-243.path, nsxt_policy_group.pr-c-mgt_ip_10-210-129-34.path, nsxt_policy_group.pr-c-mgt_ip_10-210-129-35.path, nsxt_policy_group.pr-c-mgt_ip_10-210-129-240.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc_checkpointfirewalls" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc_checkpointfirewalls"
  description  = "role: CHG0039249"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_uk-sc1-fw01.path, nsxt_policy_group.pr-c-mgt_uk-sc1-fw02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_orbis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_orbis"
  description  = "role: pr-c-mgt_grp_orbis"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_orbis-dr-nat.path, nsxt_policy_group.pr-c-mgt_ip_10-194-140-0s24.path, nsxt_policy_group.pr-c-mgt_grp_orbis-dr.path, nsxt_policy_group.pr-c-mgt_grp_orbis-live.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_152" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_152"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_152"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brsuxprein02.path, nsxt_policy_group.pr-c-mgt_sc1uxpremg30.path, nsxt_policy_group.pr-c-mgt_krakow-nat-hide.path, nsxt_policy_group.pr-c-mgt_ip_10-210-163-131.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_279" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_279"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_279"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprein01.path, nsxt_policy_group.pr-c-mgt_sc1apprein02.path, nsxt_policy_group.pr-c-mgt_sc1apprein03.path, nsxt_policy_group.pr-c-mgt_sc1apprein12.path, nsxt_policy_group.pr-c-mgt_sc1apprein13.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-stingrays-batch2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-stingrays-batch2"
  description  = "role: pr-c-mgt_grp_grp-stingrays-batch2"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprein07.path, nsxt_policy_group.pr-c-mgt_sc1apprein08.path, nsxt_policy_group.pr-c-mgt_sc1apprein09.path, nsxt_policy_group.pr-c-mgt_sc1apprein10.path, nsxt_policy_group.pr-c-mgt_sc1apprein11.path, nsxt_policy_group.pr-c-mgt_sc1apprein12.path, nsxt_policy_group.pr-c-mgt_sc1apprein13.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_282" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_282"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_282"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_lcw-cheewu.path, nsxt_policy_group.pr-c-mgt_lcw-garethdawson.path, nsxt_policy_group.pr-c-mgt_lcw-jesusingh.path, nsxt_policy_group.pr-c-mgt_lcw-mattcharlton.path, nsxt_policy_group.pr-c-mgt_lcw-scottbeadsley.path, nsxt_policy_group.pr-c-mgt_lcw-timwhaley.path, nsxt_policy_group.pr-c-mgt_stj-trading-ia-range.path, nsxt_policy_group.pr-c-mgt_lcw-shanwazmalik.path, nsxt_policy_group.pr-c-mgt_lcw-stephencarnall.path, nsxt_policy_group.pr-c-mgt_lcw-wallboardpc1.path, nsxt_policy_group.pr-c-mgt_lcw-wallboardpc2.path, nsxt_policy_group.pr-c-mgt_lcw-wallboardpc3.path, nsxt_policy_group.pr-c-mgt_lcw-alexandroschristias.path, nsxt_policy_group.pr-c-mgt_lcw-serveropsmonpc.path, nsxt_policy_group.pr-c-mgt_who-andrewfurnival.path, nsxt_policy_group.pr-c-mgt_lcw-johnnoel2.path, nsxt_policy_group.pr-c-mgt_who-jamesmoody.path, nsxt_policy_group.pr-c-mgt_who-josetalens.path, nsxt_policy_group.pr-c-mgt_who-martinkuegler.path, nsxt_policy_group.pr-c-mgt_lsj-monitoringpc2.path, nsxt_policy_group.pr-c-mgt_lcw-johnnoel.path, nsxt_policy_group.pr-c-mgt_georgepetrouis.path, nsxt_policy_group.pr-c-mgt_ianrichards.path, nsxt_policy_group.pr-c-mgt_jamesgirvan.path, nsxt_policy_group.pr-c-mgt_jarrodsmithers.path, nsxt_policy_group.pr-c-mgt_johnnoel.path, nsxt_policy_group.pr-c-mgt_neilwilson.path, nsxt_policy_group.pr-c-mgt_richardsanderson.path, nsxt_policy_group.pr-c-mgt_lcw-matthayman.path, nsxt_policy_group.pr-c-mgt_who-byrongalietta2.path, nsxt_policy_group.pr-c-mgt_whg-ltp-10-1-83-84.path, nsxt_policy_group.pr-c-mgt_lcw-garethdawson2.path, nsxt_policy_group.pr-c-mgt_gib-catalinmerluscadesk.path, nsxt_policy_group.pr-c-mgt_gib-catalinmerluscalap.path, nsxt_policy_group.pr-c-mgt_lcw-connormcnally.path, nsxt_policy_group.pr-c-mgt_lcw-cmcmullen.path, nsxt_policy_group.pr-c-mgt_lcw-danielosielczak.path, nsxt_policy_group.pr-c-mgt_lcw-joserenjikombarakaran.path, nsxt_policy_group.pr-c-mgt_usr-lcw-nbottomley.path, nsxt_policy_group.pr-c-mgt_10-1-83-229.path, nsxt_policy_group.pr-c-mgt_lcw-peteredwards.path, nsxt_policy_group.pr-c-mgt_serveroperations-27.path, nsxt_policy_group.pr-c-mgt_grp_infosec-desktops.path, nsxt_policy_group.pr-c-mgt_grp_capacity_and_monitoring_team.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_284" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_284"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_284"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprcap31.path, nsxt_policy_group.pr-c-mgt_sc1uxprcap46.path, nsxt_policy_group.pr-c-mgt_ip_10-120-132-32.path, nsxt_policy_group.pr-c-mgt_ip_10-120-132-45.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_infoblox-grid-masters" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_infoblox-grid-masters"
  description  = "role: pr-c-mgt_grp_infoblox-grid-masters"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_gibnsm01.path, nsxt_policy_group.pr-c-mgt_sc1nsm-ha.path, nsxt_policy_group.pr-c-mgt_sc1nsm01.path, nsxt_policy_group.pr-c-mgt_sc1nsm01-ha.path, nsxt_policy_group.pr-c-mgt_sc1nsm02.path, nsxt_policy_group.pr-c-mgt_sc1nsm02-ha.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_291" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_291"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_291"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-1-82-80.path, nsxt_policy_group.pr-c-mgt_grp_birstal-f5-devices.path, nsxt_policy_group.pr-c-mgt_grp_gib-f5-devices.path, nsxt_policy_group.pr-c-mgt_grp_scc-f5-devices.path, nsxt_policy_group.pr-c-mgt_grp_aws-ddos-f5s.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_299" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_299"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_299"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_uk-brs-ise01.path, nsxt_policy_group.pr-c-mgt_uk-sc1-ise01-pre-vmc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_218" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_218"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_218"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprcdb03.path, nsxt_policy_group.pr-c-mgt_sc1uxprcdb04.path, nsxt_policy_group.pr-c-mgt_scc-serviceguard-vip.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_2"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_2"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxrdk-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_grp_scc-moni-servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_160" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_160"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_160"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_capacitymonitoring.path, nsxt_policy_group.pr-c-mgt_infosec-28.path, nsxt_policy_group.pr-c-mgt_lcw-jennyfarrell.path, nsxt_policy_group.pr-c-mgt_lcw-steveibbotson.path, nsxt_policy_group.pr-c-mgt_lcw-steveibbotson2.path, nsxt_policy_group.pr-c-mgt_netsec-27.path, nsxt_policy_group.pr-c-mgt_serveroperations-27.path, nsxt_policy_group.pr-c-mgt_who-gavinjohnson.path, nsxt_policy_group.pr-c-mgt_who-raymondstrose.path, nsxt_policy_group.pr-c-mgt_who-robrussell.path, nsxt_policy_group.pr-c-mgt_who-robrussell3.path, nsxt_policy_group.pr-c-mgt_dba-jayperrikrishnaiah.path, nsxt_policy_group.pr-c-mgt_dba-keithbrailey.path, nsxt_policy_group.pr-c-mgt_dba-mattprice.path, nsxt_policy_group.pr-c-mgt_dba-nickhowe.path, nsxt_policy_group.pr-c-mgt_dba-oliverallan.path, nsxt_policy_group.pr-c-mgt_dba-oliverallan2.path, nsxt_policy_group.pr-c-mgt_dba-piotradamiak.path, nsxt_policy_group.pr-c-mgt_dba-richardanthony.path, nsxt_policy_group.pr-c-mgt_dba-richardanthony2.path, nsxt_policy_group.pr-c-mgt_dba-stephenwood.path, nsxt_policy_group.pr-c-mgt_dba-tobyhenderson.path, nsxt_policy_group.pr-c-mgt_dba-tobyhenderson2.path, nsxt_policy_group.pr-c-mgt_dba-amarbarot.path, nsxt_policy_group.pr-c-mgt_who-stephendenham.path, nsxt_policy_group.pr-c-mgt_who-miquel-polonio.path, nsxt_policy_group.pr-c-mgt_stj-jamesfryer.path, nsxt_policy_group.pr-c-mgt_stj-william-palfreman.path, nsxt_policy_group.pr-c-mgt_stj-mikebest.path, nsxt_policy_group.pr-c-mgt_lcw-joshshepheard.path, nsxt_policy_group.pr-c-mgt_is-architecture.path, nsxt_policy_group.pr-c-mgt_wh0000669.path, nsxt_policy_group.pr-c-mgt_stj-amarbarot.path, nsxt_policy_group.pr-c-mgt_krakow-nat-hide.path, nsxt_policy_group.pr-c-mgt_bg-borislavgergovski.path, nsxt_policy_group.pr-c-mgt_bg-georgibukolski.path, nsxt_policy_group.pr-c-mgt_krk-paweltulowiecki.path, nsxt_policy_group.pr-c-mgt_dbaworkstation1.path, nsxt_policy_group.pr-c-mgt_dbaworkstation2.path, nsxt_policy_group.pr-c-mgt_dba-garydennis-ip2.path, nsxt_policy_group.pr-c-mgt_krk-paweltulowiecki2.path, nsxt_policy_group.pr-c-mgt_whol5000000.path, nsxt_policy_group.pr-c-mgt_kotlarska_cloudteam.path, nsxt_policy_group.pr-c-mgt_rod-merrick-pc.path, nsxt_policy_group.pr-c-mgt_net_10-55-60-0_28.path, nsxt_policy_group.pr-c-mgt_krk-duartedecarvalho-wifi.path, nsxt_policy_group.pr-c-mgt_grp_tpam-corporate-network-access.path, nsxt_policy_group.pr-c-mgt_grp_incident_analysts.path, nsxt_policy_group.pr-c-mgt_grp_grp-tlv-office-user-lan.path, nsxt_policy_group.pr-c-mgt_grp_grand-parade-eoc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-n-redhat-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-n-redhat-servers"
  description  = "role: CHG0051845"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprnap43.path, nsxt_policy_group.pr-c-mgt_sc1uxprnap44.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-n-redhat-servers-ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-n-redhat-servers-ilo"
  description  = "role: CHG0051845"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprnap43-ilo.path, nsxt_policy_group.pr-c-mgt_sc1uxprnap44-ilo.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-fw-bk-svr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-fw-bk-svr"
  description  = "role: pr-c-mgt_grp_scc-fw-bk-svr"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprenw01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_krk-f5-admin-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_krk-f5-admin-users"
  description  = "role: pr-c-mgt_grp_krk-f5-admin-users"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_krk-mateuszstarzec-wifi.path, nsxt_policy_group.pr-c-mgt_grp_krk-jakubwalkowicz.path, nsxt_policy_group.pr-c-mgt_grp_krk-kzlomanczuk.path, nsxt_policy_group.pr-c-mgt_grp_krk-pzalewski.path, nsxt_policy_group.pr-c-mgt_grp_krk-pzurek.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_322" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_322"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_322"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1bigiq01-mgmt-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1bigiq03-mgmt-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_storage-mgt-vlans" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_storage-mgt-vlans"
  description  = "role: pr-c-mgt_grp_storage-mgt-vlans"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_san-mgmt-network2-27.path, nsxt_policy_group.pr-c-mgt_san-mgt-network-27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-xiv-array" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-xiv-array"
  description  = "role: pr-c-mgt_grp_scc-xiv-array"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_scc-xiv-array-1.path, nsxt_policy_group.pr-c-mgt_scc-xiv-array-2.path, nsxt_policy_group.pr-c-mgt_scc-xiv-array-3.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_3"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_3"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_vcenter-sddc-18-200-66-116-vmwarevmc-com.path, nsxt_policy_group.pr-c-mgt_vmcrtprapvro01-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_vmcrtdrapvro01-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc_nas_mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc_nas_mgmt"
  description  = "role: pr-c-mgt_grp_scc_nas_mgmt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1ngprcmg001.path, nsxt_policy_group.pr-c-mgt_sc1ngprcmg002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_cisco_dcmn_access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_cisco_dcmn_access"
  description  = "role: pr-c-mgt_grp_cisco_dcmn_access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brs-storage-subnet2.path, nsxt_policy_group.pr-c-mgt_gib-storage-subnet.path, nsxt_policy_group.pr-c-mgt_grp_st_johns_storage_switches.path, nsxt_policy_group.pr-c-mgt_grp_malta_san_switches.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_237" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_237"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_237"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpremn74.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn78.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_5"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_5"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_inv-cde-mgmt-lan.path, nsxt_policy_group.pr-c-mgt_sc1-cx-cde-mgmt-lan.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_trs_db_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_trs_db_servers"
  description  = "role: pr-c-mgt_grp_trs_db_servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-120-146-15.path, nsxt_policy_group.pr-c-mgt_10-120-146-16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-sc1-uxprrdb" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-sc1-uxprrdb"
  description  = "role: pr-c-mgt_grp_grp-sc1-uxprrdb"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprrdb001-nic.path, nsxt_policy_group.pr-c-mgt_sc1uxprrdb002-nic.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-sc1-uxprrdb-ilo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-sc1-uxprrdb-ilo"
  description  = "role: pr-c-mgt_grp_grp-sc1-uxprrdb-ilo"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprrdb001_ilo.path, nsxt_policy_group.pr-c-mgt_sc1uxprrdb002_ilo.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_mailhosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_mailhosts"
  description  = "role: pr-c-mgt_grp_mailhosts"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_emailhost01.path, nsxt_policy_group.pr-c-mgt_emailhost02.path, nsxt_policy_group.pr-c-mgt_emailhost03.path, nsxt_policy_group.pr-c-mgt_emailhost04.path, nsxt_policy_group.pr-c-mgt_emailhost05.path, nsxt_policy_group.pr-c-mgt_emailhost06.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_proofpoint_admins" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_proofpoint_admins"
  description  = "role: pr-c-mgt_grp_proofpoint_admins"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sd_rdp_pc.path, nsxt_policy_group.pr-c-mgt_wh0003111_proofpoint_support.path, nsxt_policy_group.pr-c-mgt_systems_support.path, nsxt_policy_group.pr-c-mgt_service_desk.path, nsxt_policy_group.pr-c-mgt_infosec.path, nsxt_policy_group.pr-c-mgt_scr_ron_jackson.path, nsxt_policy_group.pr-c-mgt_rda-andymorris.path, nsxt_policy_group.pr-c-mgt_stjohns_rda_pc.path, nsxt_policy_group.pr-c-mgt_wh0002011_stj_ops.path, nsxt_policy_group.pr-c-mgt_who-gibraltar-it.path, nsxt_policy_group.pr-c-mgt_adg-hagairazmovich.path, nsxt_policy_group.pr-c-mgt_adg-ofirariel.path, nsxt_policy_group.pr-c-mgt_adg-amirmatzas.path, nsxt_policy_group.pr-c-mgt_adg-eyalzarchi.path, nsxt_policy_group.pr-c-mgt_wh5000414.path, nsxt_policy_group.pr-c-mgt_wh5000560.path, nsxt_policy_group.pr-c-mgt_wh5000589.path, nsxt_policy_group.pr-c-mgt_wh5001304.path, nsxt_policy_group.pr-c-mgt_wh5001303.path, nsxt_policy_group.pr-c-mgt_wh5001302.path, nsxt_policy_group.pr-c-mgt_wh5001360.path, nsxt_policy_group.pr-c-mgt_james_drake_pc.path, nsxt_policy_group.pr-c-mgt_usr-sof-dimitarzafirov.path, nsxt_policy_group.pr-c-mgt_lcw-stuarthenshaw.path, nsxt_policy_group.pr-c-mgt_lcw-peteredwards.path, nsxt_policy_group.pr-c-mgt_ip_10-53-33-56.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-gib-layer7-srv-cluster3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-gib-layer7-srv-cluster3"
  description  = "role: pr-c-mgt_grp_grp-gib-layer7-srv-cluster3"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_gubux1041.path, nsxt_policy_group.pr-c-mgt_gubux1042.path, nsxt_policy_group.pr-c-mgt_gubux1043.path, nsxt_policy_group.pr-c-mgt_gubux1044.path, nsxt_policy_group.pr-c-mgt_gubux1045.path, nsxt_policy_group.pr-c-mgt_gubux1046.path, nsxt_policy_group.pr-c-mgt_gubux1047.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_188" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_188"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_188"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_lcw-nialljoseph.path, nsxt_policy_group.pr-c-mgt_grp_splunkhfcluster.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_89" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_89"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_89"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_scc-nessus-man-poc.path, nsxt_policy_group.pr-c-mgt_scc-nessus.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_137" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_137"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_137"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-46-35.path, nsxt_policy_group.pr-c-mgt_ip_10-120-46-36.path, nsxt_policy_group.pr-c-mgt_ip_10-120-46-37.path, nsxt_policy_group.pr-c-mgt_ip_10-120-46-38.path, nsxt_policy_group.pr-c-mgt_ip_10-120-46-39.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_139" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_139"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_139"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_grp_comm_vault_d_src.path, nsxt_policy_group.pr-c-mgt_grp_comm_vault_multisite.path, nsxt_policy_group.pr-c-mgt_grp_commvault-vsa-proxy-scc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-trading-oracle-cluster" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-trading-oracle-cluster"
  description  = "role: CHG0112168"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprodb001.path, nsxt_policy_group.pr-c-mgt_sc1uxprodb002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-enc-ilo-nodes" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-enc-ilo-nodes"
  description  = "role: CHG0112168"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprodb001_ilo.path, nsxt_policy_group.pr-c-mgt_sc1uxprodb002_ilo.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_179" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_179"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_179"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-143-172.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-173.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-182.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-183.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-brs-bomgar-wn-jumphosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-brs-bomgar-wn-jumphosts"
  description  = "role: CHG0115599"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brswnprcmg41-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_brswnprcmg42-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_brswnprcmg43-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_brswnprcmg44-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-po-kr-tpam-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-po-kr-tpam-access"
  description  = "role: pr-c-mgt_grp_grp-po-kr-tpam-access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-55-12-93.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-apm-cluster" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-apm-cluster"
  description  = "role: CHG0116778"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpremn10.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn11.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn12.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn13.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn15.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn105.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn106.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn107.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn108.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn120.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn121.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_203" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_203"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_203"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_scc-f5-1-mgmt.path, nsxt_policy_group.pr-c-mgt_scc-f5-2-mgmt.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_241" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_241"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_241"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brsuxdrrdb04.path, nsxt_policy_group.pr-c-mgt_grp_trs_db_servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_210" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_210"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_210"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprrdb01-tempip.path, nsxt_policy_group.pr-c-mgt_sc1uxprrdb02-tempip.path, nsxt_policy_group.pr-c-mgt_grp_liability-viewer-pds-db.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-cluster-ilo-fencing-srvs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-cluster-ilo-fencing-srvs"
  description  = "role: CHG0118285"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprrdb01-ilo-rh6.path, nsxt_policy_group.pr-c-mgt_sc1uxprrdb02-ilo-rh6.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_242" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_242"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_242"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpreap237.path, nsxt_policy_group.pr-c-mgt_sc1uxpreap238.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_243" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_243"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_243"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-120-140-200slash30.path, nsxt_policy_group.pr-c-mgt_sc1apprein08.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-orion-app-srvs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-orion-app-srvs"
  description  = "role: CHG0120636"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnpremn74-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnpremn75-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnpremn77-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnpremn78-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_ld6wnpremn74-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_ld6wnpremn75-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_ld6wnpremn77-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_ld6wnpremn78-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_ld6wnpremn79-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_zabbix-monitoring" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_zabbix-monitoring"
  description  = "role: CHG0121232"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_cust-zabprx-prod-01.path, nsxt_policy_group.pr-c-mgt_cust-zabprx-prod-01-2.path, nsxt_policy_group.pr-c-mgt_10-195-201-171.path, nsxt_policy_group.pr-c-mgt_172-16-201-171.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_252" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_252"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_252"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1ux304.path, nsxt_policy_group.pr-c-mgt_sc1ux305.path, nsxt_policy_group.pr-c-mgt_sc1ux307.path, nsxt_policy_group.pr-c-mgt_sc1uxprcdb03.path, nsxt_policy_group.pr-c-mgt_sc1uxprcdb04.path, nsxt_policy_group.pr-c-mgt_sc1uxprxdb01.path, nsxt_policy_group.pr-c-mgt_sc1uxprxdb02.path, nsxt_policy_group.pr-c-mgt_grp_primaryinformixservers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_storage-labm" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_storage-labm"
  description  = "role: CHG0126163"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_labm1001.path, nsxt_policy_group.pr-c-mgt_labm1002.path, nsxt_policy_group.pr-c-mgt_labm1003.path, nsxt_policy_group.pr-c-mgt_labm1009.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_us-las-it-team" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_us-las-it-team"
  description  = "role: pr-c-mgt_grp_us-las-it-team"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_usnv-ahuts-dwx.path, nsxt_policy_group.pr-c-mgt_usnv-chmoo-lwx.path, nsxt_policy_group.pr-c-mgt_usnv-rmusni-dwx.path, nsxt_policy_group.pr-c-mgt_usnv-scron-dw7.path, nsxt_policy_group.pr-c-mgt_usnv-tring-dwx.path, nsxt_policy_group.pr-c-mgt_wh0004101.path, nsxt_policy_group.pr-c-mgt_wh0004111.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-wh-us-team" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-wh-us-team"
  description  = "role: CHG0135451"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_us-aaronhutsell.path, nsxt_policy_group.pr-c-mgt_us-bartopiola.path, nsxt_policy_group.pr-c-mgt_us-chrismoore.path, nsxt_policy_group.pr-c-mgt_us-reinermusni.path, nsxt_policy_group.pr-c-mgt_us-roderickvilla.path, nsxt_policy_group.pr-c-mgt_us-seancronan.path, nsxt_policy_group.pr-c-mgt_us-tommyringstad.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_7"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_7"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprcwb41.path, nsxt_policy_group.pr-c-mgt_sc1uxprcwb42.path, nsxt_policy_group.pr-c-mgt_sc1uxprcap31.path, nsxt_policy_group.pr-c-mgt_sc1uxprcap32.path, nsxt_policy_group.pr-c-mgt_sc1uxprcap45.path, nsxt_policy_group.pr-c-mgt_sc1uxprcap46.path, nsxt_policy_group.pr-c-mgt_ip_10-120-137-11.path, nsxt_policy_group.pr-c-mgt_ip_10-120-137-12.path, nsxt_policy_group.pr-c-mgt_grp_sccinformixservers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_44"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_44"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-140-200.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-201.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-202.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-203.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-204.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-205.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-206.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-207.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-208.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-209.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-scc-vmc-service-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-scc-vmc-service-mgmt"
  description  = "role: pr-c-mgt_grp_grp-scc-vmc-service-mgmt"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-126-204-0s22.path, nsxt_policy_group.pr-c-mgt_ip_10-126-236-0s22.path, nsxt_policy_group.pr-c-mgt_ip_10-126-252-0s22.path, nsxt_policy_group.pr-c-mgt_ip_10-156-2-0s25.path, nsxt_policy_group.pr-c-mgt_ip_10-156-2-128s25.path, nsxt_policy_group.pr-c-mgt_ip_10-156-3-0s25.path, nsxt_policy_group.pr-c-mgt_ip_10-126-193-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-126-194-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-126-76-0s22.path, nsxt_policy_group.pr-c-mgt_ip_10-156-0-128s25.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_59"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_59"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brswnprcmg41-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_brswnprcmg42-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_brswnprcmg43-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_brswnprcmg44-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg41-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg42-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg43-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1wnprcmg44-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_62"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_62"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_scc-xiv-array-1.path, nsxt_policy_group.pr-c-mgt_scc-xiv-array-2.path, nsxt_policy_group.pr-c-mgt_scc-xiv-array-3.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_68"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_68"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_grp_scc-non-whc-prod-esxi-hosts.path, nsxt_policy_group.pr-c-mgt_grp_scc-oracle-prod-esxi-hosts.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_san-switches" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_san-switches"
  description  = "role: pr-c-mgt_grp_san-switches"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_scc-san-sw5.path, nsxt_policy_group.pr-c-mgt_scc-san-sw6.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-164.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-165.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-166.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-167.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_pr_c_mgt_local_subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_pr_c_mgt_local_subnets"
  description  = "role: pr-c-mgt_grp_pr_c_mgt_local_subnets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-128-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-130-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-131-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-132-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-133-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-134-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-135-0s25.path, nsxt_policy_group.pr-c-mgt_ip_10-120-136-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-137-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-139-224s27.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-141-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-128s27.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-160s27.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-64s27.path, nsxt_policy_group.pr-c-mgt_ip_10-120-143-96s27.path, nsxt_policy_group.pr-c-mgt_ip_10-120-160-160s27.path, nsxt_policy_group.pr-c-mgt_ip_10-120-80-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_ise-psn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_ise-psn"
  description  = "role: CHG0137261"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_uk-sc1-ise02-pre-vmc.path, nsxt_policy_group.pr-c-mgt_uk-brs-ise02.path, nsxt_policy_group.pr-c-mgt_gi-mpl-ise01.path, nsxt_policy_group.pr-c-mgt_uk-sc1-ise01.path, nsxt_policy_group.pr-c-mgt_uk-sc1-ise02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_brs_citrix_controllers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_brs_citrix_controllers"
  description  = "role: pr-c-mgt_grp_brs_citrix_controllers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-210-39-105.path, nsxt_policy_group.pr-c-mgt_ip_10-210-39-106.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_6"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_6"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1prappsc02-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1prapvc01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-aws-ddos-nonprod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-aws-ddos-nonprod"
  description  = "role: CHG0150097"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_aws-ddos-np1-100-78-48-0s24.path, nsxt_policy_group.pr-c-mgt_aws-ddos-np1-100-78-49-0s24.path, nsxt_policy_group.pr-c-mgt_aws-ddos-np1-100-78-50-0s24.path, nsxt_policy_group.pr-c-mgt_ip_100-78-51-0s24.path, nsxt_policy_group.pr-c-mgt_ip_100-78-52-0s24.path, nsxt_policy_group.pr-c-mgt_ip_100-78-53-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_vmc-sddcs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_vmc-sddcs"
  description  = "role: pr-c-mgt_grp_vmc-sddcs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_vmc-whc-dev-10-126-76-0_22.path, nsxt_policy_group.pr-c-mgt_vmc-whc-pp-10-126-188-0_22.path, nsxt_policy_group.pr-c-mgt_ip_10-156-3-128s25.path, nsxt_policy_group.pr-c-mgt_ip_10-156-4-0s25.path, nsxt_policy_group.pr-c-mgt_ip_10-156-4-128s25.path, nsxt_policy_group.pr-c-mgt_ip_10-156-5-0s24.path, nsxt_policy_group.pr-c-mgt_grp_vmc-sddc-retail-production.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_ras-vpn-pool"
  description  = "role: pr-c-mgt_grp_ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_grp_ld6-ras-vpn-pool.path, nsxt_policy_group.pr-c-mgt_grp_sc1-ras-vpn-pool.path, nsxt_policy_group.pr-c-mgt_grp_mrg-ras-vpn-pool.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_whgroup_ad_servers-chg0144834" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_whgroup_ad_servers-chg0144834"
  description  = "role: pr-c-mgt_grp_whgroup_ad_servers-chg0144834"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_bfawnpredc01.path, nsxt_policy_group.pr-c-mgt_brswnpredc01_ip_10-210-194-11.path, nsxt_policy_group.pr-c-mgt_brswnpredc02.path, nsxt_policy_group.pr-c-mgt_brswnpredc03.path, nsxt_policy_group.pr-c-mgt_gibwnpredc02.path, nsxt_policy_group.pr-c-mgt_gibwnpredc03.path, nsxt_policy_group.pr-c-mgt_irewnprdc01.path, nsxt_policy_group.pr-c-mgt_irewnprdc02.path, nsxt_policy_group.pr-c-mgt_nvawnprdc01.path, nsxt_policy_group.pr-c-mgt_nvawnprdc02.path, nsxt_policy_group.pr-c-mgt_krawnpredc01.path, nsxt_policy_group.pr-c-mgt_krawnpredc02.path, nsxt_policy_group.pr-c-mgt_ld6wnpredc01-new.path, nsxt_policy_group.pr-c-mgt_ld6wnpredc02-new.path, nsxt_policy_group.pr-c-mgt_mnlwnpredc02_ip_10-123-197-11.path, nsxt_policy_group.pr-c-mgt_mnlwnpredc03.path, nsxt_policy_group.pr-c-mgt_sc1wnpredc01_ip_10-120-194-11.path, nsxt_policy_group.pr-c-mgt_sc1wnpredc02_ip_10-120-194-12.path, nsxt_policy_group.pr-c-mgt_sc1wnpredc03.path, nsxt_policy_group.pr-c-mgt_sc1wnpredc04.path, nsxt_policy_group.pr-c-mgt_sc1wnpredc05.path, nsxt_policy_group.pr-c-mgt_sc1wnpredc08.path, nsxt_policy_group.pr-c-mgt_sofwnpredc01.path, nsxt_policy_group.pr-c-mgt_sofwnpredc02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_euc_mgmt_server-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_euc_mgmt_server-group-chg0142765"
  description  = "role: pr-c-mgt_grp_euc_mgmt_server-group-chg0142765"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brsapprcmg002-group-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_on_premise_datacentre_vlans-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_on_premise_datacentre_vlans-group-chg0142765"
  description  = "role: pr-c-mgt_grp_on_premise_datacentre_vlans-group-chg0142765"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-210-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-180-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-112-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-19-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_wh_nets-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_wh_nets-chg0143200"
  description  = "role: pr-c-mgt_grp_wh_nets-chg0143200"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-0-0-0s8.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_splunk_heavy_forwarders-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_splunk_heavy_forwarders-chg0143200"
  description  = "role: pr-c-mgt_grp_splunk_heavy_forwarders-chg0143200"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpremn002.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn003.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_splunk_deployment_server-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_splunk_deployment_server-chg0143200"
  description  = "role: pr-c-mgt_grp_splunk_deployment_server-chg0143200"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_splunkdeployment-sc1-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_wh_nets-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_wh_nets-chg0142763"
  description  = "role: pr-c-mgt_grp_wh_nets-chg0142763"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_splunk_heavy_forwarders-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_splunk_heavy_forwarders-chg0142763"
  description  = "role: pr-c-mgt_grp_splunk_heavy_forwarders-chg0142763"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpremn002.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn003.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_splunk_deployment_server-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_splunk_deployment_server-chg0142763"
  description  = "role: pr-c-mgt_grp_splunk_deployment_server-chg0142763"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_splunkdeployment-sc1-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-commvault-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-commvault-svrs"
  description  = "role: CHG0112231"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprbkms01.path, nsxt_policy_group.pr-c-mgt_sc1uxprbkms02.path, nsxt_policy_group.pr-c-mgt_sc1wnprbkcs01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-gib-commvault-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-gib-commvault-svrs"
  description  = "role: CHG0112231"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_gibuxprbkms01.path, nsxt_policy_group.pr-c-mgt_gibuxprbkms02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-ld6-commvault-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-ld6-commvault-svrs"
  description  = "role: CHG0112231"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ld6uxprbkms03.path, nsxt_policy_group.pr-c-mgt_ld6uxprbkms04.path, nsxt_policy_group.pr-c-mgt_ld6wnprbkcs01.path, nsxt_policy_group.pr-c-mgt_ld6uxprbkms01.path, nsxt_policy_group.pr-c-mgt_ld6uxprbkms02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_splunkhfcluster" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_splunkhfcluster"
  description  = "role: pr-c-mgt_grp_splunkhfcluster"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpremn002-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn003-prod-williamhill-plc.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn004-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_rundeck-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_rundeck-servers"
  description  = "role: pr-c-mgt_grp_rundeck-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpreap237.path, nsxt_policy_group.pr-c-mgt_sc1uxpreap238.path, nsxt_policy_group.pr-c-mgt_sc1uxpreap239.path, nsxt_policy_group.pr-c-mgt_sc1uxpreap242.path, nsxt_policy_group.pr-c-mgt_sc1uxrdk.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_50"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_50"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-44-25.path, nsxt_policy_group.pr-c-mgt_ip_10-120-44-26.path, nsxt_policy_group.pr-c-mgt_ip_10-120-44-27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_200"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_200"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brsux910.path, nsxt_policy_group.pr-c-mgt_gibux910.path, nsxt_policy_group.pr-c-mgt_ld6uxpreds01.path, nsxt_policy_group.pr-c-mgt_sc1uxpreds01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_wily-svrs_all" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_wily-svrs_all"
  description  = "role: pr-c-mgt_grp_wily-svrs_all"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_grp_wily_svrs_brs.path, nsxt_policy_group.pr-c-mgt_grp_wily_svrs_scc.path, nsxt_policy_group.pr-c-mgt_grp_wily_svrs_gib.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_wily-access-group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_wily-access-group"
  description  = "role: pr-c-mgt_grp_wily-access-group"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-0-0-0s8.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_webproxies-cx-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_webproxies-cx-scc"
  description  = "role: pr-c-mgt_grp_webproxies-cx-scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_10-121-5-0slash24.path, nsxt_policy_group.pr-c-mgt_10-121-7-0slash24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_hp-oneview-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_hp-oneview-servers"
  description  = "role: pr-c-mgt_grp_hp-oneview-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpremg25-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_ossec-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_ossec-servers"
  description  = "role: pr-c-mgt_grp_ossec-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprcmn001.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_wh-group-ad-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_wh-group-ad-servers"
  description  = "role: pr-c-mgt_grp_wh-group-ad-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_mnlwnpredc02_ip_10-123-197-11.path, nsxt_policy_group.pr-c-mgt_brswnpredc02.path, nsxt_policy_group.pr-c-mgt_brswnpredc03.path, nsxt_policy_group.pr-c-mgt_gibwnpredc02.path, nsxt_policy_group.pr-c-mgt_gibwnpredc03.path, nsxt_policy_group.pr-c-mgt_sc1wnpredc03.path, nsxt_policy_group.pr-c-mgt_sc1wnpredc04.path, nsxt_policy_group.pr-c-mgt_sc1wnpredc05.path, nsxt_policy_group.pr-c-mgt_sc1wnpredc08.path, nsxt_policy_group.pr-c-mgt_ld6wnpredc01-new.path, nsxt_policy_group.pr-c-mgt_ld6wnpredc02-new.path, nsxt_policy_group.pr-c-mgt_bfawnpredc01.path, nsxt_policy_group.pr-c-mgt_krawnpredc01.path, nsxt_policy_group.pr-c-mgt_krawnpredc02.path, nsxt_policy_group.pr-c-mgt_sofwnpredc01.path, nsxt_policy_group.pr-c-mgt_sofwnpredc02.path, nsxt_policy_group.pr-c-mgt_mnlwnpredc03.path, nsxt_policy_group.pr-c-mgt_brswnpredc01_ip_10-210-194-11.path, nsxt_policy_group.pr-c-mgt_sc1wnpredc01_ip_10-120-194-11.path, nsxt_policy_group.pr-c-mgt_sc1wnpredc02_ip_10-120-194-12.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_145" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_145"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_145"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_grp_esteem-jumphosts.path, nsxt_policy_group.pr-c-mgt_grp_rds-servers-gib.path, nsxt_policy_group.pr-c-mgt_grp_rds-servers-scc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_vsphere_access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_vsphere_access"
  description  = "role: pr-c-mgt_grp_vsphere_access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_grp_cloud_nets_for_vsphere_access.path, nsxt_policy_group.pr-c-mgt_grp_vsphere_mgmt_nets.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_infoblox-all-dns-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_infoblox-all-dns-servers"
  description  = "role: pr-c-mgt_grp_infoblox-all-dns-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brsns01.path, nsxt_policy_group.pr-c-mgt_brsns02.path, nsxt_policy_group.pr-c-mgt_gibns01.path, nsxt_policy_group.pr-c-mgt_gibns02.path, nsxt_policy_group.pr-c-mgt_sccns01.path, nsxt_policy_group.pr-c-mgt_sccns02.path, nsxt_policy_group.pr-c-mgt_ld6ns01.path, nsxt_policy_group.pr-c-mgt_ld6ns02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-c-dns-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-c-dns-servers"
  description  = "role: CHG0018398"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_uk-brs-ns01.path, nsxt_policy_group.pr-c-mgt_uk-sc1-ns01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-c-wsus-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-c-wsus-servers"
  description  = "role: CHG0018398"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_uk-scc-wsus.path, nsxt_policy_group.pr-c-mgt_stj-wsus.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-c-trendav-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-c-trendav-servers"
  description  = "role: CHG0018398"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnprein07.path, nsxt_policy_group.pr-c-mgt_stj-tmcm01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-c-syslog-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-c-syslog-servers"
  description  = "role: CHG0018398"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_uk-sc1-sm02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-c-ntp-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-c-ntp-servers"
  description  = "role: CHG0018398"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ntp001.path, nsxt_policy_group.pr-c-mgt_ntp002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-c-status-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-c-status-servers"
  description  = "role: pr-c-mgt_grp_grp-pr-c-status-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpremg30.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-c-katello-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-c-katello-servers"
  description  = "role: pr-c-mgt_grp_grp-pr-c-katello-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sccuxstnmg01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_mail-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_mail-servers"
  description  = "role: pr-c-mgt_grp_mail-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brs-proofpoint.path, nsxt_policy_group.pr-c-mgt_scc-mail.path, nsxt_policy_group.pr-c-mgt_stj-proofpoint.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_uim-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_uim-servers"
  description  = "role: CHG0079749,CHG0119559"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_brsuxpremn65.path, nsxt_policy_group.pr-c-mgt_brsuxpremn66.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn65.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn66.path, nsxt_policy_group.pr-c-mgt_ld6uxpremn13.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_105" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_105"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_105"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-65-68.path, nsxt_policy_group.pr-c-mgt_ip_10-210-65-68.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_rds-kms-server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_rds-kms-server"
  description  = "role: KMS/RDS license servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1wnpremg002.path, nsxt_policy_group.pr-c-mgt_brswndremg002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-migrated_network_221" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-migrated_network_221"
  description  = "role: pr-c-mgt_grp_scc-migrated_network_221"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-121-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-c-ad-child" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-c-ad-child"
  description  = "role: CHG0014122"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-194-13.path, nsxt_policy_group.pr-c-mgt_ip_10-120-194-14.path, nsxt_policy_group.pr-c-mgt_ip_10-120-194-15.path, nsxt_policy_group.pr-c-mgt_ip_10-120-194-18.path, nsxt_policy_group.pr-c-mgt_ip_10-120-194-16.path, nsxt_policy_group.pr-c-mgt_ip_10-120-194-17.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-pr-c-ad-parent" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-pr-c-ad-parent"
  description  = "role: CHG0014122"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-194-11.path, nsxt_policy_group.pr-c-mgt_ip_10-120-194-12.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_stj-networksteam" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_stj-networksteam"
  description  = "role: pr-c-mgt_grp_stj-networksteam"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_stj-asim-ibrahim.path, nsxt_policy_group.pr-c-mgt_stj-nick-simpson.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_tss-aws-net" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_tss-aws-net"
  description  = "role: pr-c-mgt_grp_tss-aws-net"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_100-79-0-0s17.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-layer7-gateway" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-layer7-gateway"
  description  = "role: pr-c-mgt_grp_scc-layer7-gateway"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1apprcwb01.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb02.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb03.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb04.path, nsxt_policy_group.pr-c-mgt_sc1apprcwb11.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_systemengineers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_systemengineers"
  description  = "role: Gareth Sephton owned"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_who-llanosnunez.path, nsxt_policy_group.pr-c-mgt_lcw-andrewdonachie.path, nsxt_policy_group.pr-c-mgt_lcw-chriswren.path, nsxt_policy_group.pr-c-mgt_lcw-chriswren2.path, nsxt_policy_group.pr-c-mgt_lcw-danferry.path, nsxt_policy_group.pr-c-mgt_lcw-garethsephton.path, nsxt_policy_group.pr-c-mgt_lcw-markpetrie.path, nsxt_policy_group.pr-c-mgt_lcw-ravisingh.path, nsxt_policy_group.pr-c-mgt_lcw-richardhampshire.path, nsxt_policy_group.pr-c-mgt_lcw-richardscott.path, nsxt_policy_group.pr-c-mgt_lcw-roblewis.path, nsxt_policy_group.pr-c-mgt_lcw-stevewilson.path, nsxt_policy_group.pr-c-mgt_lcw-tomfield.path, nsxt_policy_group.pr-c-mgt_who-alastairmontgomery.path, nsxt_policy_group.pr-c-mgt_who-joncandlin.path, nsxt_policy_group.pr-c-mgt_who-marcuscampbell.path, nsxt_policy_group.pr-c-mgt_who-neilbellamy.path, nsxt_policy_group.pr-c-mgt_who-neilbellamy2.path, nsxt_policy_group.pr-c-mgt_usr-wpp-agalindo.path, nsxt_policy_group.pr-c-mgt_usr-wpp-agalindo2.path, nsxt_policy_group.pr-c-mgt_who-chrishall.path, nsxt_policy_group.pr-c-mgt_who-karolstatkiewicz.path, nsxt_policy_group.pr-c-mgt_stj-nathanflynn.path, nsxt_policy_group.pr-c-mgt_who-amcadam.path, nsxt_policy_group.pr-c-mgt_lcw-alancatto.path, nsxt_policy_group.pr-c-mgt_gib-karolstatkiewicz.path, nsxt_policy_group.pr-c-mgt_who-amcadam2.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_orbis-dr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_orbis-dr"
  description  = "role: pr-c-mgt_grp_orbis-dr"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-193-30-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_orbis-live" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_orbis-live"
  description  = "role: pr-c-mgt_grp_orbis-live"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-194-20-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_infosec-desktops" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_infosec-desktops"
  description  = "role: pr-c-mgt_grp_infosec-desktops"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_infosec-sdavies.path, nsxt_policy_group.pr-c-mgt_infosec-jmcintyre.path, nsxt_policy_group.pr-c-mgt_infosec-sanderson.path, nsxt_policy_group.pr-c-mgt_infosec-sbond1.path, nsxt_policy_group.pr-c-mgt_infosec-sbond.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_capacity_and_monitoring_team" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_capacity_and_monitoring_team"
  description  = "role: CHG0016414, CHG0022913, CHG0038464"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_lcw-summtjain.path, nsxt_policy_group.pr-c-mgt_lcw-andrewlongmuir.path, nsxt_policy_group.pr-c-mgt_lcw-johnsnow.path, nsxt_policy_group.pr-c-mgt_lcw-davewalsh.path, nsxt_policy_group.pr-c-mgt_lcw-richthomas.path, nsxt_policy_group.pr-c-mgt_lcw-samillingworth.path, nsxt_policy_group.pr-c-mgt_lcw-stevemoyes.path, nsxt_policy_group.pr-c-mgt_lcw-davidwalshlaptop.path, nsxt_policy_group.pr-c-mgt_lcw-summitjain.path, nsxt_policy_group.pr-c-mgt_ia-jennyfarrell.path, nsxt_policy_group.pr-c-mgt_ia-robrussell.path, nsxt_policy_group.pr-c-mgt_ia-steveibbotson.path, nsxt_policy_group.pr-c-mgt_lcw-stevenhammersley.path, nsxt_policy_group.pr-c-mgt_who-cezarygajdzinski.path, nsxt_policy_group.pr-c-mgt_ip_10-1-82-166.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-138.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-139.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-140.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-78.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-93.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-118.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-38.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-137.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-141.path, nsxt_policy_group.pr-c-mgt_ip_10-1-83-142.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_birstal-f5-devices" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_birstal-f5-devices"
  description  = "role: pr-c-mgt_grp_birstal-f5-devices"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-210-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-210-140-12.path, nsxt_policy_group.pr-c-mgt_ip_10-211-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-212-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-213-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-214-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-215-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-216-140-11.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_gib-f5-devices" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_gib-f5-devices"
  description  = "role: pr-c-mgt_grp_gib-f5-devices"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-180-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-180-140-12.path, nsxt_policy_group.pr-c-mgt_ip_10-180-140-13.path, nsxt_policy_group.pr-c-mgt_ip_10-180-140-14.path, nsxt_policy_group.pr-c-mgt_ip_10-180-140-15.path, nsxt_policy_group.pr-c-mgt_ip_10-180-140-16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-f5-devices" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-f5-devices"
  description  = "role: pr-c-mgt_grp_scc-f5-devices"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-120-140-11.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-12.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-13.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-14.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-15.path, nsxt_policy_group.pr-c-mgt_ip_10-120-140-16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_tpam-corporate-network-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_tpam-corporate-network-access"
  description  = "role: CHG0067336"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_scr-group-1st-network.path, nsxt_policy_group.pr-c-mgt_scr-group-2nd-network.path, nsxt_policy_group.pr-c-mgt_scr-online-1st-network.path, nsxt_policy_group.pr-c-mgt_scr-online-2nd-network.path, nsxt_policy_group.pr-c-mgt_wpp-3rd-network.path, nsxt_policy_group.pr-c-mgt_wpp-5th-network.path, nsxt_policy_group.pr-c-mgt_wpp-6th-network.path, nsxt_policy_group.pr-c-mgt_wpp-grnd-network.path, nsxt_policy_group.pr-c-mgt_wpp-group-3rd-network.path, nsxt_policy_group.pr-c-mgt_wpp-group-4th-network.path, nsxt_policy_group.pr-c-mgt_wpp-online-network.path, nsxt_policy_group.pr-c-mgt_grp_net-10-1-78-0-23.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_incident_analysts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_incident_analysts"
  description  = "role: CHG0022161"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_stj-trading-ia-range.path, nsxt_policy_group.pr-c-mgt_lsj-monitoringpc2.path, nsxt_policy_group.pr-c-mgt_ia-paulsenior.path, nsxt_policy_group.pr-c-mgt_ia-elizabethlaing.path, nsxt_policy_group.pr-c-mgt_ip_10-1-18-144.path, nsxt_policy_group.pr-c-mgt_ip_10-1-18-183.path, nsxt_policy_group.pr-c-mgt_ip_10-1-18-35.path, nsxt_policy_group.pr-c-mgt_ip_10-1-18-36.path, nsxt_policy_group.pr-c-mgt_ip_10-1-18-43.path, nsxt_policy_group.pr-c-mgt_ip_10-1-18-57.path, nsxt_policy_group.pr-c-mgt_ip_10-1-18-62.path, nsxt_policy_group.pr-c-mgt_ip_10-1-18-64.path, nsxt_policy_group.pr-c-mgt_ip_10-1-66-144.path, nsxt_policy_group.pr-c-mgt_ip_10-1-66-183.path, nsxt_policy_group.pr-c-mgt_ip_10-1-66-35.path, nsxt_policy_group.pr-c-mgt_ip_10-1-66-36.path, nsxt_policy_group.pr-c-mgt_ip_10-1-66-43.path, nsxt_policy_group.pr-c-mgt_ip_10-1-66-57.path, nsxt_policy_group.pr-c-mgt_ip_10-1-66-62.path, nsxt_policy_group.pr-c-mgt_ip_10-1-66-64.path, nsxt_policy_group.pr-c-mgt_ip_10-1-82-128s27.path, nsxt_policy_group.pr-c-mgt_ip_10-1-22-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grp-tlv-office-user-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grp-tlv-office-user-lan"
  description  = "role: pr-c-mgt_grp_grp-tlv-office-user-lan"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_usr-tlv-wh5001456.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_grand-parade-eoc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_grand-parade-eoc"
  description  = "role: pr-c-mgt_grp_grand-parade-eoc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-55-13-253.path, nsxt_policy_group.pr-c-mgt_ip_10-55-13-254.path, nsxt_policy_group.pr-c-mgt_ip_10-55-13-255.path, nsxt_policy_group.pr-c-mgt_ip_10-55-14-18.path, nsxt_policy_group.pr-c-mgt_ip_10-55-14-19.path, nsxt_policy_group.pr-c-mgt_ip_10-55-14-20.path, nsxt_policy_group.pr-c-mgt_ip_10-55-225-253.path, nsxt_policy_group.pr-c-mgt_ip_10-55-225-254.path, nsxt_policy_group.pr-c-mgt_ip_10-55-225-255.path, nsxt_policy_group.pr-c-mgt_ip_10-55-226-18.path, nsxt_policy_group.pr-c-mgt_ip_10-55-226-19.path, nsxt_policy_group.pr-c-mgt_ip_10-55-226-20.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_krk-jakubwalkowicz" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_krk-jakubwalkowicz"
  description  = "role: pr-c-mgt_grp_krk-jakubwalkowicz"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_krk-jakubwalkowicz-lan.path, nsxt_policy_group.pr-c-mgt_krk-jakubwalkowicz-wifi.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_krk-kzlomanczuk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_krk-kzlomanczuk"
  description  = "role: pr-c-mgt_grp_krk-kzlomanczuk"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_krk-kzlomanczuk-lan.path, nsxt_policy_group.pr-c-mgt_krk-kzlomanczuk-wifi.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_krk-pzalewski" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_krk-pzalewski"
  description  = "role: pr-c-mgt_grp_krk-pzalewski"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_krk-pzalewski-lan.path, nsxt_policy_group.pr-c-mgt_krk-pzalewski-wifi.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_krk-pzurek" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_krk-pzurek"
  description  = "role: pr-c-mgt_grp_krk-pzurek"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_krk-pzurek-lan.path, nsxt_policy_group.pr-c-mgt_krk-pzurek-wifi.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_st_johns_storage_switches" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_st_johns_storage_switches"
  description  = "role: pr-c-mgt_grp_st_johns_storage_switches"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-100-9-11.path, nsxt_policy_group.pr-c-mgt_ip_10-100-9-12.path, nsxt_policy_group.pr-c-mgt_ip_10-100-9-13.path, nsxt_policy_group.pr-c-mgt_ip_10-100-9-14.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_malta_san_switches" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_malta_san_switches"
  description  = "role: pr-c-mgt_grp_malta_san_switches"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-129-11-8.path, nsxt_policy_group.pr-c-mgt_ip_10-129-11-7.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_comm_vault_d_src" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_comm_vault_d_src"
  description  = "role: pr-c-mgt_grp_comm_vault_d_src"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-112-46-30.path, nsxt_policy_group.pr-c-mgt_ip_10-112-46-33.path, nsxt_policy_group.pr-c-mgt_ip_10-112-46-34.path, nsxt_policy_group.pr-c-mgt_ip_10-120-46-30.path, nsxt_policy_group.pr-c-mgt_ip_10-120-46-31.path, nsxt_policy_group.pr-c-mgt_ip_10-120-46-32.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_comm_vault_multisite" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_comm_vault_multisite"
  description  = "role: pr-c-mgt_grp_comm_vault_multisite"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-112-46-30.path, nsxt_policy_group.pr-c-mgt_ip_10-112-46-33.path, nsxt_policy_group.pr-c-mgt_ip_10-112-46-34.path, nsxt_policy_group.pr-c-mgt_ip_10-120-46-30.path, nsxt_policy_group.pr-c-mgt_ip_10-180-46-31.path, nsxt_policy_group.pr-c-mgt_ip_10-180-46-32.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_commvault-vsa-proxy-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_commvault-vsa-proxy-scc"
  description  = "role: CHG0111326"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprbkvs01.path, nsxt_policy_group.pr-c-mgt_sc1uxprbkvs02.path, nsxt_policy_group.pr-c-mgt_sc1uxprbkvs03.path, nsxt_policy_group.pr-c-mgt_sc1uxprbkvs04.path, nsxt_policy_group.pr-c-mgt_sc1uxprbkvs05.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_liability-viewer-pds-db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_liability-viewer-pds-db"
  description  = "role: pr-c-mgt_grp_liability-viewer-pds-db"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprrdb01-mg.path, nsxt_policy_group.pr-c-mgt_sc1uxprrdb02-mg.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_primaryinformixservers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_primaryinformixservers"
  description  = "role: pr-c-mgt_grp_primaryinformixservers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprxdb01.path, nsxt_policy_group.pr-c-mgt_sc1uxprxdb02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_sccinformixservers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_sccinformixservers"
  description  = "role: pr-c-mgt_grp_sccinformixservers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxprcdb03.path, nsxt_policy_group.pr-c-mgt_sc1uxprcdb04.path, nsxt_policy_group.pr-c-mgt_sc1uxprxdb01.path, nsxt_policy_group.pr-c-mgt_sc1uxprxdb02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-non-whc-prod-esxi-hosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-non-whc-prod-esxi-hosts"
  description  = "role: pr-c-mgt_grp_scc-non-whc-prod-esxi-hosts"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-126-225-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-126-226-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_scc-oracle-prod-esxi-hosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_scc-oracle-prod-esxi-hosts"
  description  = "role: pr-c-mgt_grp_scc-oracle-prod-esxi-hosts"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-126-241-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-126-242-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_vmc-sddc-retail-production" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_vmc-sddc-retail-production"
  description  = "role: pr-c-mgt_grp_vmc-sddc-retail-production"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_vmc-retail-production-vsphere-mgmt.path, nsxt_policy_group.pr-c-mgt_vmc-retail-production-10-233-0-0s24.path, nsxt_policy_group.pr-c-mgt_vmc-retail-production-services-mgmt.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_ld6-ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_ld6-ras-vpn-pool"
  description  = "role: pr-c-mgt_grp_ld6-ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_192-168-48-0s20.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_sc1-ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_sc1-ras-vpn-pool"
  description  = "role: pr-c-mgt_grp_sc1-ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_192-168-12-0s22.path, nsxt_policy_group.pr-c-mgt_ip_192-168-16-0s22.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_mrg-ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_mrg-ras-vpn-pool"
  description  = "role: pr-c-mgt_grp_mrg-ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-30-200-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-30-202-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-40-200-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-40-202-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-130-200-0s23.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_wily_svrs_brs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_wily_svrs_brs"
  description  = "role: pr-c-mgt_grp_wily_svrs_brs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-210-163-95.path, nsxt_policy_group.pr-c-mgt_ip_10-210-163-96.path, nsxt_policy_group.pr-c-mgt_ip_10-210-163-97.path, nsxt_policy_group.pr-c-mgt_ip_10-210-163-98.path, nsxt_policy_group.pr-c-mgt_ip_10-210-163-99.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_wily_svrs_scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_wily_svrs_scc"
  description  = "role: pr-c-mgt_grp_wily_svrs_scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_sc1uxpremn105.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn106.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn107.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn108.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn120.path, nsxt_policy_group.pr-c-mgt_sc1uxpremn121.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-31.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-32.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-33.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-34.path, nsxt_policy_group.pr-c-mgt_ip_10-120-163-36.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_wily_svrs_gib" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_wily_svrs_gib"
  description  = "role: pr-c-mgt_grp_wily_svrs_gib"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-180-163-211.path, nsxt_policy_group.pr-c-mgt_ip_10-180-163-212.path, nsxt_policy_group.pr-c-mgt_ip_10-180-163-213.path, nsxt_policy_group.pr-c-mgt_ip_10-180-163-214.path, nsxt_policy_group.pr-c-mgt_ip_10-180-163-218.path, nsxt_policy_group.pr-c-mgt_ip_10-180-163-102.path, nsxt_policy_group.pr-c-mgt_ip_10-180-163-220.path, nsxt_policy_group.pr-c-mgt_ip_10-180-163-221.path, nsxt_policy_group.pr-c-mgt_ip_10-180-163-40.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_esteem-jumphosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_esteem-jumphosts"
  description  = "role: pr-c-mgt_grp_esteem-jumphosts"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_esteem-jumphost-brs.path, nsxt_policy_group.pr-c-mgt_esteem-jumphost-scc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_rds-servers-gib" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_rds-servers-gib"
  description  = "role: pr-c-mgt_grp_rds-servers-gib"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-180-141-41.path, nsxt_policy_group.pr-c-mgt_ip_10-180-141-42.path, nsxt_policy_group.pr-c-mgt_ip_10-180-141-43.path, nsxt_policy_group.pr-c-mgt_ip_10-180-141-44.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_cloud_nets_for_vsphere_access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_cloud_nets_for_vsphere_access"
  description  = "role: CHG0111493"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_ip_10-191-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-193-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-195-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-201-224-0s20.path, nsxt_policy_group.pr-c-mgt_ip_10-208-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-241-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-242-10-0s24.path, nsxt_policy_group.pr-c-mgt_ip_10-116-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-121-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-122-0-0s16.path, nsxt_policy_group.pr-c-mgt_ip_10-181-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-mgt_grp_net-10-1-78-0-23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp_net-10-1-78-0-23"
  description  = "role: pr-c-mgt_grp_net-10-1-78-0-23"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-mgt_citywalk78.path, nsxt_policy_group.pr-c-mgt_stjohns79.path]
    }
  }
}
