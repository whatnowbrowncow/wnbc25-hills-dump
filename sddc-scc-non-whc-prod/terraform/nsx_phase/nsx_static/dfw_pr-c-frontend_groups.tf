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

resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-163-73" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-163-73"
  description  = "role: pr-c-frontend_ip_10-120-163-73, ip: [10.120.163.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-134-253" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-134-253"
  description  = "role: pr-c-frontend_ip_10-120-134-253, ip: [10.120.134.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.253"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-142-164" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-142-164"
  description  = "role: pr-c-frontend_ip_10-180-142-164, ip: [10.180.142.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.142.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-163-134" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-163-134"
  description  = "role: pr-c-frontend_ip_10-120-163-134, ip: [10.120.163.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.134"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-70"
  description  = "role: pr-c-frontend_ip_10-120-46-70, ip: [10.120.46.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-114-135-221" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-114-135-221"
  description  = "role: pr-c-frontend_ip_10-114-135-221, ip: [10.114.135.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.114.135.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-99-10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-99-10"
  description  = "role: pr-c-frontend_ip_10-120-99-10, ip: [10.120.99.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-101-10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-101-10"
  description  = "role: pr-c-frontend_ip_10-120-101-10, ip: [10.120.101.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.101.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-48-122" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-48-122"
  description  = "role: pr-c-frontend_ip_10-120-48-122, ip: [10.120.48.122]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.48.122"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-143-170" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-143-170"
  description  = "role: pr-c-frontend_ip_10-210-143-170, ip: [10.210.143.170]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.143.170"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-39-108" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-39-108"
  description  = "role: pr-c-frontend_ip_10-120-39-108, ip: [10.120.39.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-69-200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-69-200"
  description  = "role: pr-c-frontend_ip_10-120-69-200, ip: [10.120.69.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-163-89" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-163-89"
  description  = "role: pr-c-frontend_ip_10-120-163-89, ip: [10.120.163.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.89"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-163-33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-163-33"
  description  = "role: pr-c-frontend_ip_10-120-163-33, ip: [10.120.163.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-146-115" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-146-115"
  description  = "role: pr-c-frontend_ip_10-120-146-115, ip: [10.120.146.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-146-116" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-146-116"
  description  = "role: pr-c-frontend_ip_10-120-146-116, ip: [10.120.146.116]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.116"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-146-206" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-146-206"
  description  = "role: pr-c-frontend_ip_10-210-146-206, ip: [10.210.146.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.146.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-64-152" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-64-152"
  description  = "role: pr-c-frontend_ip_10-120-64-152, ip: [10.120.64.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.64.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-64-152" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-64-152"
  description  = "role: pr-c-frontend_ip_10-210-64-152, ip: [10.210.64.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.64.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-64-140" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-64-140"
  description  = "role: pr-c-frontend_ip_10-210-64-140, ip: [10.210.64.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.64.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-64-142" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-64-142"
  description  = "role: pr-c-frontend_ip_10-210-64-142, ip: [10.210.64.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.64.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-64-147" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-64-147"
  description  = "role: pr-c-frontend_ip_10-210-64-147, ip: [10.210.64.147]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.64.147"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-39-143" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-39-143"
  description  = "role: pr-c-frontend_ip_10-120-39-143, ip: [10.120.39.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.143"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-39-142" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-39-142"
  description  = "role: pr-c-frontend_ip_10-120-39-142, ip: [10.120.39.142]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.142"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-39-147" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-39-147"
  description  = "role: pr-c-frontend_ip_10-120-39-147, ip: [10.120.39.147]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.147"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-39-148" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-39-148"
  description  = "role: pr-c-frontend_ip_10-120-39-148, ip: [10.120.39.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-163-140" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-163-140"
  description  = "role: pr-c-frontend_ip_10-120-163-140, ip: [10.120.163.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-140" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-140"
  description  = "role: pr-c-frontend_ip_10-180-163-140, ip: [10.180.163.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-145" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-145"
  description  = "role: pr-c-frontend_ip_10-180-163-145, ip: [10.180.163.145]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.145"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-163-20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-163-20"
  description  = "role: pr-c-frontend_ip_10-210-163-20, ip: [10.210.163.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-163-97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-163-97"
  description  = "role: pr-c-frontend_ip_10-120-163-97, ip: [10.120.163.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-163-98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-163-98"
  description  = "role: pr-c-frontend_ip_10-120-163-98, ip: [10.120.163.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-10"
  description  = "role: pr-c-frontend_ip_10-120-46-10, ip: [10.120.46.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-11"
  description  = "role: pr-c-frontend_ip_10-120-46-11, ip: [10.120.46.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-12"
  description  = "role: pr-c-frontend_ip_10-120-46-12, ip: [10.120.46.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-13"
  description  = "role: pr-c-frontend_ip_10-120-46-13, ip: [10.120.46.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-14"
  description  = "role: pr-c-frontend_ip_10-120-46-14, ip: [10.120.46.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-15"
  description  = "role: pr-c-frontend_ip_10-120-46-15, ip: [10.120.46.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-138-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-138-15"
  description  = "role: pr-c-frontend_ip_10-180-138-15, ip: [10.180.138.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.138.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-46-35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-46-35"
  description  = "role: pr-c-frontend_ip_10-180-46-35, ip: [10.180.46.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-46-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-46-36"
  description  = "role: pr-c-frontend_ip_10-180-46-36, ip: [10.180.46.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-46-37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-46-37"
  description  = "role: pr-c-frontend_ip_10-180-46-37, ip: [10.180.46.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-46-38" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-46-38"
  description  = "role: pr-c-frontend_ip_10-180-46-38, ip: [10.180.46.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-46-39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-46-39"
  description  = "role: pr-c-frontend_ip_10-180-46-39, ip: [10.180.46.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-46-10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-46-10"
  description  = "role: pr-c-frontend_ip_10-210-46-10, ip: [10.210.46.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-46-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-46-11"
  description  = "role: pr-c-frontend_ip_10-210-46-11, ip: [10.210.46.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-46-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-46-12"
  description  = "role: pr-c-frontend_ip_10-210-46-12, ip: [10.210.46.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-46-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-46-13"
  description  = "role: pr-c-frontend_ip_10-210-46-13, ip: [10.210.46.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-46-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-46-14"
  description  = "role: pr-c-frontend_ip_10-210-46-14, ip: [10.210.46.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-46-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-46-15"
  description  = "role: pr-c-frontend_ip_10-210-46-15, ip: [10.210.46.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-46-16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-46-16"
  description  = "role: pr-c-frontend_ip_10-210-46-16, ip: [10.210.46.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-46-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-46-17"
  description  = "role: pr-c-frontend_ip_10-210-46-17, ip: [10.210.46.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-1-29-38" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-1-29-38"
  description  = "role: pr-c-frontend_ip_10-1-29-38, ip: [10.1.29.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-1-29-39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-1-29-39"
  description  = "role: pr-c-frontend_ip_10-1-29-39, ip: [10.1.29.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-43"
  description  = "role: pr-c-frontend_ip_10-120-46-43, ip: [10.120.46.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-44"
  description  = "role: pr-c-frontend_ip_10-120-46-44, ip: [10.120.46.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-45"
  description  = "role: pr-c-frontend_ip_10-120-46-45, ip: [10.120.46.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-46"
  description  = "role: pr-c-frontend_ip_10-120-46-46, ip: [10.120.46.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-47" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-47"
  description  = "role: pr-c-frontend_ip_10-120-46-47, ip: [10.120.46.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-48"
  description  = "role: pr-c-frontend_ip_10-120-46-48, ip: [10.120.46.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-49" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-49"
  description  = "role: pr-c-frontend_ip_10-120-46-49, ip: [10.120.46.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-99-61" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-99-61"
  description  = "role: pr-c-frontend_ip_10-120-99-61, ip: [10.120.99.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-44-25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-44-25"
  description  = "role: pr-c-frontend_ip_10-120-44-25, ip: [10.120.44.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-44-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-44-26"
  description  = "role: pr-c-frontend_ip_10-120-44-26, ip: [10.120.44.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-44-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-44-27"
  description  = "role: pr-c-frontend_ip_10-120-44-27, ip: [10.120.44.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-52-220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-52-220"
  description  = "role: pr-c-frontend_ip_10-180-52-220, ip: [10.180.52.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.52.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-52-221" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-52-221"
  description  = "role: pr-c-frontend_ip_10-180-52-221, ip: [10.180.52.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.52.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-52-222" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-52-222"
  description  = "role: pr-c-frontend_ip_10-180-52-222, ip: [10.180.52.222]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.52.222"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-1-82-109" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-1-82-109"
  description  = "role: pr-c-frontend_ip_10-1-82-109, ip: [10.1.82.109]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.109"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-1-82-178" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-1-82-178"
  description  = "role: pr-c-frontend_ip_10-1-82-178, ip: [10.1.82.178]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.178"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-1-82-183" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-1-82-183"
  description  = "role: pr-c-frontend_ip_10-1-82-183, ip: [10.1.82.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-1-82-189" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-1-82-189"
  description  = "role: pr-c-frontend_ip_10-1-82-189, ip: [10.1.82.189]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.189"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-1-82-235" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-1-82-235"
  description  = "role: pr-c-frontend_ip_10-1-82-235, ip: [10.1.82.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-30"
  description  = "role: pr-c-frontend_ip_10-120-46-30, ip: [10.120.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-32"
  description  = "role: pr-c-frontend_ip_10-120-46-32, ip: [10.120.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-39-103" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-39-103"
  description  = "role: pr-c-frontend_ip_10-120-39-103, ip: [10.120.39.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-39-104" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-39-104"
  description  = "role: pr-c-frontend_ip_10-120-39-104, ip: [10.120.39.104]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.104"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-39-105" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-39-105"
  description  = "role: pr-c-frontend_ip_10-120-39-105, ip: [10.120.39.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-39-106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-39-106"
  description  = "role: pr-c-frontend_ip_10-120-39-106, ip: [10.120.39.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-44-28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-44-28"
  description  = "role: pr-c-frontend_ip_10-180-44-28, ip: [10.180.44.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.44.28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-38" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-38"
  description  = "role: pr-c-frontend_ip_10-180-163-38, ip: [10.180.163.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-39"
  description  = "role: pr-c-frontend_ip_10-180-163-39, ip: [10.180.163.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-45"
  description  = "role: pr-c-frontend_ip_10-180-163-45, ip: [10.180.163.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-46"
  description  = "role: pr-c-frontend_ip_10-180-163-46, ip: [10.180.163.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-65-68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-65-68"
  description  = "role: pr-c-frontend_ip_10-120-65-68, ip: [10.120.65.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.65.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-65-68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-65-68"
  description  = "role: pr-c-frontend_ip_10-210-65-68, ip: [10.210.65.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.65.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-163-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-163-31"
  description  = "role: pr-c-frontend_ip_10-120-163-31, ip: [10.120.163.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-163-32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-163-32"
  description  = "role: pr-c-frontend_ip_10-120-163-32, ip: [10.120.163.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-163-34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-163-34"
  description  = "role: pr-c-frontend_ip_10-120-163-34, ip: [10.120.163.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-163-36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-163-36"
  description  = "role: pr-c-frontend_ip_10-120-163-36, ip: [10.120.163.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-163-95" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-163-95"
  description  = "role: pr-c-frontend_ip_10-210-163-95, ip: [10.210.163.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-163-96" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-163-96"
  description  = "role: pr-c-frontend_ip_10-210-163-96, ip: [10.210.163.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-163-97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-163-97"
  description  = "role: pr-c-frontend_ip_10-210-163-97, ip: [10.210.163.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-163-98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-163-98"
  description  = "role: pr-c-frontend_ip_10-210-163-98, ip: [10.210.163.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-163-99" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-163-99"
  description  = "role: pr-c-frontend_ip_10-210-163-99, ip: [10.210.163.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-211" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-211"
  description  = "role: pr-c-frontend_ip_10-180-163-211, ip: [10.180.163.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-212" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-212"
  description  = "role: pr-c-frontend_ip_10-180-163-212, ip: [10.180.163.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-213" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-213"
  description  = "role: pr-c-frontend_ip_10-180-163-213, ip: [10.180.163.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-214" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-214"
  description  = "role: pr-c-frontend_ip_10-180-163-214, ip: [10.180.163.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-218" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-218"
  description  = "role: pr-c-frontend_ip_10-180-163-218, ip: [10.180.163.218]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.218"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-102" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-102"
  description  = "role: pr-c-frontend_ip_10-180-163-102, ip: [10.180.163.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-220" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-220"
  description  = "role: pr-c-frontend_ip_10-180-163-220, ip: [10.180.163.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-221" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-221"
  description  = "role: pr-c-frontend_ip_10-180-163-221, ip: [10.180.163.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-163-40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-163-40"
  description  = "role: pr-c-frontend_ip_10-180-163-40, ip: [10.180.163.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-44-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-44-0s23"
  description  = "role: pr-c-frontend_ip_10-120-44-0s23, ip: [10.120.44.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-0s24"
  description  = "role: pr-c-frontend_ip_10-120-46-0s24, ip: [10.120.46.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-134-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-134-0s24"
  description  = "role: pr-c-frontend_ip_10-120-134-0s24, ip: [10.120.134.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-39-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-39-0s24"
  description  = "role: pr-c-frontend_ip_10-120-39-0s24, ip: [10.120.39.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-46-0s25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-46-0s25"
  description  = "role: pr-c-frontend_ip_10-120-46-0s25, ip: [10.120.46.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-118-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-118-0-0s16"
  description  = "role: pr-c-frontend_ip_10-118-0-0s16, ip: [10.118.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-141-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-141-0s24"
  description  = "role: pr-c-frontend_ip_10-120-141-0s24, ip: [10.120.141.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_100-74-144-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_100-74-144-0s23"
  description  = "role: pr-c-frontend_ip_100-74-144-0s23, ip: [100.74.144.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.74.144.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-66-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-66-0s24"
  description  = "role: pr-c-frontend_ip_10-120-66-0s24, ip: [10.120.66.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.66.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_0-0-0-0s5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_0-0-0-0s5"
  description  = "role: pr-c-frontend_ip_0-0-0-0s5, ip: [0.0.0.0/5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["0.0.0.0/5"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_8-0-0-0s7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_8-0-0-0s7"
  description  = "role: pr-c-frontend_ip_8-0-0-0s7, ip: [8.0.0.0/7]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["8.0.0.0/7"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_11-0-0-0s8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_11-0-0-0s8"
  description  = "role: pr-c-frontend_ip_11-0-0-0s8, ip: [11.0.0.0/8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["11.0.0.0/8"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_12-0-0-0s6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_12-0-0-0s6"
  description  = "role: pr-c-frontend_ip_12-0-0-0s6, ip: [12.0.0.0/6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["12.0.0.0/6"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_16-0-0-0s4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_16-0-0-0s4"
  description  = "role: pr-c-frontend_ip_16-0-0-0s4, ip: [16.0.0.0/4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["16.0.0.0/4"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_32-0-0-0s3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_32-0-0-0s3"
  description  = "role: pr-c-frontend_ip_32-0-0-0s3, ip: [32.0.0.0/3]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["32.0.0.0/3"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_64-0-0-0s2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_64-0-0-0s2"
  description  = "role: pr-c-frontend_ip_64-0-0-0s2, ip: [64.0.0.0/2]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["64.0.0.0/2"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_128-0-0-0s3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_128-0-0-0s3"
  description  = "role: pr-c-frontend_ip_128-0-0-0s3, ip: [128.0.0.0/3]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["128.0.0.0/3"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_160-0-0-0s5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_160-0-0-0s5"
  description  = "role: pr-c-frontend_ip_160-0-0-0s5, ip: [160.0.0.0/5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["160.0.0.0/5"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_168-0-0-0s6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_168-0-0-0s6"
  description  = "role: pr-c-frontend_ip_168-0-0-0s6, ip: [168.0.0.0/6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["168.0.0.0/6"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_172-0-0-0s12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_172-0-0-0s12"
  description  = "role: pr-c-frontend_ip_172-0-0-0s12, ip: [172.0.0.0/12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.0.0.0/12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_172-32-0-0s11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_172-32-0-0s11"
  description  = "role: pr-c-frontend_ip_172-32-0-0s11, ip: [172.32.0.0/11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.32.0.0/11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_172-64-0-0s10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_172-64-0-0s10"
  description  = "role: pr-c-frontend_ip_172-64-0-0s10, ip: [172.64.0.0/10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.64.0.0/10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_172-128-0-0s9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_172-128-0-0s9"
  description  = "role: pr-c-frontend_ip_172-128-0-0s9, ip: [172.128.0.0/9]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.128.0.0/9"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_173-0-0-0s8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_173-0-0-0s8"
  description  = "role: pr-c-frontend_ip_173-0-0-0s8, ip: [173.0.0.0/8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["173.0.0.0/8"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_174-0-0-0s7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_174-0-0-0s7"
  description  = "role: pr-c-frontend_ip_174-0-0-0s7, ip: [174.0.0.0/7]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["174.0.0.0/7"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_176-0-0-0s4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_176-0-0-0s4"
  description  = "role: pr-c-frontend_ip_176-0-0-0s4, ip: [176.0.0.0/4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["176.0.0.0/4"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_192-0-0-0s9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_192-0-0-0s9"
  description  = "role: pr-c-frontend_ip_192-0-0-0s9, ip: [192.0.0.0/9]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.0.0.0/9"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_192-128-0-0s11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_192-128-0-0s11"
  description  = "role: pr-c-frontend_ip_192-128-0-0s11, ip: [192.128.0.0/11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.128.0.0/11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_192-160-0-0s13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_192-160-0-0s13"
  description  = "role: pr-c-frontend_ip_192-160-0-0s13, ip: [192.160.0.0/13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.160.0.0/13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_192-169-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_192-169-0-0s16"
  description  = "role: pr-c-frontend_ip_192-169-0-0s16, ip: [192.169.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.169.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_192-170-0-0s15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_192-170-0-0s15"
  description  = "role: pr-c-frontend_ip_192-170-0-0s15, ip: [192.170.0.0/15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.170.0.0/15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_192-172-0-0s14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_192-172-0-0s14"
  description  = "role: pr-c-frontend_ip_192-172-0-0s14, ip: [192.172.0.0/14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.172.0.0/14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_192-176-0-0s12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_192-176-0-0s12"
  description  = "role: pr-c-frontend_ip_192-176-0-0s12, ip: [192.176.0.0/12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.176.0.0/12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_192-192-0-0s10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_192-192-0-0s10"
  description  = "role: pr-c-frontend_ip_192-192-0-0s10, ip: [192.192.0.0/10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.192.0.0/10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_193-0-0-0s8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_193-0-0-0s8"
  description  = "role: pr-c-frontend_ip_193-0-0-0s8, ip: [193.0.0.0/8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["193.0.0.0/8"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_194-0-0-0s7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_194-0-0-0s7"
  description  = "role: pr-c-frontend_ip_194-0-0-0s7, ip: [194.0.0.0/7]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["194.0.0.0/7"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_196-0-0-0s6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_196-0-0-0s6"
  description  = "role: pr-c-frontend_ip_196-0-0-0s6, ip: [196.0.0.0/6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["196.0.0.0/6"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_200-0-0-0s5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_200-0-0-0s5"
  description  = "role: pr-c-frontend_ip_200-0-0-0s5, ip: [200.0.0.0/5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["200.0.0.0/5"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_208-0-0-0s4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_208-0-0-0s4"
  description  = "role: pr-c-frontend_ip_208-0-0-0s4, ip: [208.0.0.0/4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["208.0.0.0/4"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-33-160s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-33-160s27"
  description  = "role: pr-c-frontend_ip_10-120-33-160s27, ip: [10.120.33.160/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.160/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-38-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-38-0s24"
  description  = "role: pr-c-frontend_ip_10-120-38-0s24, ip: [10.120.38.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.38.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-33-0s29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-33-0s29"
  description  = "role: pr-c-frontend_ip_10-120-33-0s29, ip: [10.120.33.0/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.0/29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-1-28-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-1-28-0s23"
  description  = "role: pr-c-frontend_ip_10-1-28-0s23, ip: [10.1.28.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-209-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-209-0-0s16"
  description  = "role: pr-c-frontend_ip_10-209-0-0s16, ip: [10.209.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.209.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-194-140-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-194-140-0s24"
  description  = "role: pr-c-frontend_ip_10-194-140-0s24, ip: [10.194.140.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.194.140.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-39-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-39-0s24"
  description  = "role: pr-c-frontend_ip_10-210-39-0s24, ip: [10.210.39.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.39.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-100-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-100-0s24"
  description  = "role: pr-c-frontend_ip_10-120-100-0s24, ip: [10.120.100.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-101-0s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-101-0s27"
  description  = "role: pr-c-frontend_ip_10-120-101-0s27, ip: [10.120.101.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.101.0/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-102-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-102-0s24"
  description  = "role: pr-c-frontend_ip_10-120-102-0s24, ip: [10.120.102.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.102.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-132-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-132-0s24"
  description  = "role: pr-c-frontend_ip_10-120-132-0s24, ip: [10.120.132.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-39-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-39-0s24"
  description  = "role: pr-c-frontend_ip_10-180-39-0s24, ip: [10.180.39.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.39.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-160-32s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-160-32s27"
  description  = "role: pr-c-frontend_ip_10-120-160-32s27, ip: [10.120.160.32/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.160.32/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-32-64s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-32-64s27"
  description  = "role: pr-c-frontend_ip_10-120-32-64s27, ip: [10.120.32.64/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.32.64/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-37-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-37-0s24"
  description  = "role: pr-c-frontend_ip_10-120-37-0s24, ip: [10.120.37.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-48-96s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-48-96s27"
  description  = "role: pr-c-frontend_ip_10-120-48-96s27, ip: [10.120.48.96/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.48.96/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-50-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-50-0s24"
  description  = "role: pr-c-frontend_ip_10-120-50-0s24, ip: [10.120.50.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.50.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-52-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-52-0s24"
  description  = "role: pr-c-frontend_ip_10-120-52-0s24, ip: [10.120.52.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.52.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-156-5-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-156-5-0s24"
  description  = "role: pr-c-frontend_ip_10-156-5-0s24, ip: [10.156.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-0-0s16"
  description  = "role: pr-c-frontend_ip_10-120-0-0s16, ip: [10.120.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-210-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-210-0-0s16"
  description  = "role: pr-c-frontend_ip_10-210-0-0s16, ip: [10.210.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-180-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-180-0-0s16"
  description  = "role: pr-c-frontend_ip_10-180-0-0s16, ip: [10.180.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-112-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-112-0-0s16"
  description  = "role: pr-c-frontend_ip_10-112-0-0s16, ip: [10.112.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-19-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-19-0-0s16"
  description  = "role: pr-c-frontend_ip_10-19-0-0s16, ip: [10.19.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-0-0-0s8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-0-0-0s8"
  description  = "role: pr-c-frontend_ip_10-0-0-0s8, ip: [10.0.0.0/8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.0.0.0/8"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-67-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-67-0s24"
  description  = "role: pr-c-frontend_ip_10-120-67-0s24, ip: [10.120.67.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.67.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-72-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-72-0s24"
  description  = "role: pr-c-frontend_ip_10-120-72-0s24, ip: [10.120.72.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.72.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-121-0-0s16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-121-0-0s16"
  description  = "role: pr-c-frontend_ip_10-121-0-0s16, ip: [10.121.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-129-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-129-0s24"
  description  = "role: pr-c-frontend_ip_10-120-129-0s24, ip: [10.120.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-131-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-131-0s24"
  description  = "role: pr-c-frontend_ip_10-120-131-0s24, ip: [10.120.131.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-133-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-133-0s24"
  description  = "role: pr-c-frontend_ip_10-120-133-0s24, ip: [10.120.133.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.133.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-136-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-136-0s24"
  description  = "role: pr-c-frontend_ip_10-120-136-0s24, ip: [10.120.136.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-137-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-137-0s24"
  description  = "role: pr-c-frontend_ip_10-120-137-0s24, ip: [10.120.137.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.137.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-143-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-143-0s24"
  description  = "role: pr-c-frontend_ip_10-120-143-0s24, ip: [10.120.143.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-145-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-145-0s24"
  description  = "role: pr-c-frontend_ip_10-120-145-0s24, ip: [10.120.145.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-146-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-146-0s24"
  description  = "role: pr-c-frontend_ip_10-120-146-0s24, ip: [10.120.146.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-147-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-147-0s24"
  description  = "role: pr-c-frontend_ip_10-120-147-0s24, ip: [10.120.147.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.147.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-148-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-148-0s24"
  description  = "role: pr-c-frontend_ip_10-120-148-0s24, ip: [10.120.148.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-149-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-149-0s24"
  description  = "role: pr-c-frontend_ip_10-120-149-0s24, ip: [10.120.149.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-152-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-152-0s24"
  description  = "role: pr-c-frontend_ip_10-120-152-0s24, ip: [10.120.152.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.152.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-153-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-153-0s24"
  description  = "role: pr-c-frontend_ip_10-120-153-0s24, ip: [10.120.153.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-159-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-159-0s24"
  description  = "role: pr-c-frontend_ip_10-120-159-0s24, ip: [10.120.159.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-162-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-162-0s24"
  description  = "role: pr-c-frontend_ip_10-120-162-0s24, ip: [10.120.162.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.162.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-163-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-163-0s24"
  description  = "role: pr-c-frontend_ip_10-120-163-0s24, ip: [10.120.163.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-180-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-180-0s24"
  description  = "role: pr-c-frontend_ip_10-120-180-0s24, ip: [10.120.180.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-193-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-193-0s24"
  description  = "role: pr-c-frontend_ip_10-120-193-0s24, ip: [10.120.193.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-194-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-194-0s24"
  description  = "role: pr-c-frontend_ip_10-120-194-0s24, ip: [10.120.194.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-195-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-195-0s24"
  description  = "role: pr-c-frontend_ip_10-120-195-0s24, ip: [10.120.195.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.195.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-120-64-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-120-64-0s24"
  description  = "role: pr-c-frontend_ip_10-120-64-0s24, ip: [10.120.64.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.64.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_192-168-48-0s20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_192-168-48-0s20"
  description  = "role: pr-c-frontend_ip_192-168-48-0s20, ip: [192.168.48.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.48.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_192-168-12-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_192-168-12-0s22"
  description  = "role: pr-c-frontend_ip_192-168-12-0s22, ip: [192.168.12.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.12.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_192-168-16-0s22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_192-168-16-0s22"
  description  = "role: pr-c-frontend_ip_192-168-16-0s22, ip: [192.168.16.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.16.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-30-200-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-30-200-0s24"
  description  = "role: pr-c-frontend_ip_10-30-200-0s24, ip: [10.30.200.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.30.200.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-30-202-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-30-202-0s24"
  description  = "role: pr-c-frontend_ip_10-30-202-0s24, ip: [10.30.202.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.30.202.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-40-200-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-40-200-0s24"
  description  = "role: pr-c-frontend_ip_10-40-200-0s24, ip: [10.40.200.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.200.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-40-202-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-40-202-0s24"
  description  = "role: pr-c-frontend_ip_10-40-202-0s24, ip: [10.40.202.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.202.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ip_10-130-200-0s23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ip_10-130-200-0s23"
  description  = "role: pr-c-frontend_ip_10-130-200-0s23, ip: [10.130.200.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.130.200.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibux1023" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibux1023"
  description  = "role: pr-c-frontend_gibux1023, ip: [10.180.37.190]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.37.190"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_int-api-bonus-proxy-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_int-api-bonus-proxy-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.181.5.82]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.181.5.82"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_int-api-sports-pds-cmapi-whapi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_int-api-sports-pds-cmapi-whapi"
  description  = "role: pr-c-frontend_int-api-sports-pds-cmapi-whapi, ip: [10.121.5.86]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.5.86"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprcap31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprcap31"
  description  = "role: pr-c-frontend_sc1uxprcap31, ip: [10.120.50.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.50.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_informix-db-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_informix-db-vip"
  description  = "role: pr-c-frontend_informix-db-vip, ip: [10.120.52.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.52.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprcap32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprcap32"
  description  = "role: pr-c-frontend_sc1uxprcap32, ip: [10.120.50.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.50.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_int-lb-cde-cp-aws-noncde-proxy-sc1-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_int-lb-cde-cp-aws-noncde-proxy-sc1-prod-williamhill-plc"
  description  = "role: CHG0141205, ip: [10.120.44.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcmg001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcmg001"
  description  = "role: pr-c-frontend_sc1apprcmg001, ip: [10.120.136.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_citrix-network-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_citrix-network-24"
  description  = "role: pr-c-frontend_citrix-network-24, ip: [10.120.39.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_int-lb-cdebackoffice-sc1-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_int-lb-cdebackoffice-sc1-prod-williamhill-plc"
  description  = "role: pr-c-frontend_int-lb-cdebackoffice-sc1-prod-williamhill-plc, ip: [10.120.44.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_int-lb-cdebackoffice-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_int-lb-cdebackoffice-williamhill-plc"
  description  = "role: pr-c-frontend_int-lb-cdebackoffice-williamhill-plc, ip: [10.180.44.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.44.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprtdb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprtdb001"
  description  = "role: CHG0123808, ip: [10.120.177.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.177.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_was01n-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_was01n-prod-williamhill-plc"
  description  = "role: CHG0139029, ip: [10.210.64.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.64.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_svr-openbet-offshore-cde" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_svr-openbet-offshore-cde"
  description  = "role: pr-c-frontend_svr-openbet-offshore-cde, ip: [10.180.74.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.74.54"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_int-lb-cdeproxy" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_int-lb-cdeproxy"
  description  = "role: pr-c-frontend_int-lb-cdeproxy, ip: [10.180.44.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.44.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprefs04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprefs04"
  description  = "role: pr-c-frontend_sc1wnprefs04, ip: [10.120.39.109]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.109"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswnprefs04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswnprefs04"
  description  = "role: pr-c-frontend_brswnprefs04, ip: [10.210.39.109]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.39.109"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprein01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprein01"
  description  = "role: pr-c-frontend_sc1wnprein01, ip: [10.120.163.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswnpredb005" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswnpredb005"
  description  = "role: pr-c-frontend_brswnpredb005, ip: [10.210.39.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.39.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_splunkdeployment-sc1-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_splunkdeployment-sc1-prod-williamhill-plc"
  description  = "role: CHG0142763, ip: [10.120.163.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprens01-bovip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprens01-bovip"
  description  = "role: CHG0126550, ip: [10.120.69.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.207"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsapprcmg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsapprcmg002"
  description  = "role: pr-c-frontend_brsapprcmg002, ip: [10.210.163.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn77" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn77"
  description  = "role: pr-c-frontend_sc1uxpremn77, ip: [10.120.163.77]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.77"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprbkcs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprbkcs01"
  description  = "role: pr-c-frontend_sc1wnprbkcs01, ip: [10.120.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_prodjde" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_prodjde"
  description  = "role: pr-c-frontend_prodjde, ip: [10.1.27.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.27.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_informix-hdr-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_informix-hdr-vip"
  description  = "role: pr-c-frontend_informix-hdr-vip, ip: [10.120.48.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.48.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_archive-db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_archive-db"
  description  = "role: pr-c-frontend_archive-db, ip: [10.120.48.118]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.48.118"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsux311" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsux311"
  description  = "role: pr-c-frontend_brsux311, ip: [10.210.52.121]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.52.121"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_scc-nessus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-nessus"
  description  = "role: pr-c-frontend_scc-nessus, ip: [10.120.143.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnpremn20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnpremn20"
  description  = "role: pr-c-frontend_sc1wnpremn20, ip: [10.120.163.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_vpn-uk-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_vpn-uk-24"
  description  = "role: CHG0022234, ip: [192.168.2.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sccuxstnmg03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sccuxstnmg03"
  description  = "role: pr-c-frontend_sccuxstnmg03, ip: [10.120.163.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_emailhost02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_emailhost02"
  description  = "role: pr-c-frontend_emailhost02, ip: [10.120.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_emailhost01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_emailhost01"
  description  = "role: pr-c-frontend_emailhost01, ip: [10.120.33.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_net_10-120-37-0m24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_net_10-120-37-0m24"
  description  = "role: pr-c-frontend_net_10-120-37-0m24, ip: [10.120.37.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1isilon-ssip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1isilon-ssip"
  description  = "role: pr-c-frontend_sc1isilon-ssip, ip: [10.120.46.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_scc-nas-ip-range" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-nas-ip-range"
  description  = "role: SCC NAS IP range, ip: [10.120.46.40, 10.120.46.41, 10.120.46.42, 10.120.46.43, 10.120.46.44, 10.120.46.45, 10.120.46.46, 10.120.46.47, 10.120.46.48, 10.120.46.49, 10.120.46.50, 10.120.46.51, 10.120.46.52, 10.120.46.53, 10.120.46.54, 10.120.46.55, 10.120.46.56, 10.120.46.57, 10.120.46.58, 10.120.46.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.40", "10.120.46.41", "10.120.46.42", "10.120.46.43", "10.120.46.44", "10.120.46.45", "10.120.46.46", "10.120.46.47", "10.120.46.48", "10.120.46.49", "10.120.46.50", "10.120.46.51", "10.120.46.52", "10.120.46.53", "10.120.46.54", "10.120.46.55", "10.120.46.56", "10.120.46.57", "10.120.46.58", "10.120.46.59"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_isilon-cluster-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_isilon-cluster-scc"
  description  = "role: pr-c-frontend_isilon-cluster-scc, ip: [10.120.46.10, 10.120.46.11, 10.120.46.12, 10.120.46.13, 10.120.46.14, 10.120.46.15, 10.120.46.16, 10.120.46.17, 10.120.46.18, 10.120.46.19, 10.120.46.20, 10.120.46.21, 10.120.46.22, 10.120.46.23, 10.120.46.24, 10.120.46.25, 10.120.46.26, 10.120.46.27, 10.120.46.28, 10.120.46.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.10", "10.120.46.11", "10.120.46.12", "10.120.46.13", "10.120.46.14", "10.120.46.15", "10.120.46.16", "10.120.46.17", "10.120.46.18", "10.120.46.19", "10.120.46.20", "10.120.46.21", "10.120.46.22", "10.120.46.23", "10.120.46.24", "10.120.46.25", "10.120.46.26", "10.120.46.27", "10.120.46.28", "10.120.46.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprnap71" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprnap71"
  description  = "role: pr-c-frontend_sc1uxprnap71, ip: [10.120.99.71]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.71"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_net_10-210-39-0m24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_net_10-210-39-0m24"
  description  = "role: pr-c-frontend_net_10-210-39-0m24, ip: [10.210.39.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.39.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnpredb005" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnpredb005"
  description  = "role: pr-c-frontend_sc1wnpredb005, ip: [10.120.39.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-whapi-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-whapi-servers"
  description  = "role: CHG0119859, ip: [10.120.37.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremg22-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremg22-prod-williamhill-plc"
  description  = "role: pr-c-frontend_sc1uxpremg22-prod-williamhill-plc, ip: [10.120.163.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibux998" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibux998"
  description  = "role: pr-c-frontend_gibux998, ip: [10.180.163.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibprcap01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibprcap01"
  description  = "role: pr-c-frontend_gibprcap01, ip: [10.180.46.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprepvs05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprepvs05"
  description  = "role: CHG0146699, ip: [10.120.194.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.61"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprelic01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprelic01"
  description  = "role: CHG0146699, ip: [10.120.39.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_classa-8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_classa-8"
  description  = "role: CHG0018964, ip: [10.0.0.0/8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.0.0.0/8"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprein12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprein12"
  description  = "role: pr-c-frontend_sc1wnprein12, ip: [10.120.163.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.132"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_scc_snow_collector" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc_snow_collector"
  description  = "role: pr-c-frontend_scc_snow_collector, ip: [10.120.163.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnpremg30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnpremg30"
  description  = "role: pr-c-frontend_sc1wnpremg30, ip: [10.120.136.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_scc_internal_01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc_internal_01"
  description  = "role: pr-c-frontend_scc_internal_01, ip: [10.120.37.191]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.191"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb017" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb017"
  description  = "role: pr-c-frontend_sc1apprcwb017, ip: [10.120.37.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb018" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb018"
  description  = "role: pr-c-frontend_sc1apprcwb018, ip: [10.120.37.209]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.209"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb019" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb019"
  description  = "role: pr-c-frontend_sc1apprcwb019, ip: [10.120.37.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb020" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb020"
  description  = "role: pr-c-frontend_sc1apprcwb020, ip: [10.120.37.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb021" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb021"
  description  = "role: pr-c-frontend_sc1apprcwb021, ip: [10.120.37.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb022" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb022"
  description  = "role: pr-c-frontend_sc1apprcwb022, ip: [10.120.37.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb023" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb023"
  description  = "role: pr-c-frontend_sc1apprcwb023, ip: [10.120.37.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb024" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb024"
  description  = "role: pr-c-frontend_sc1apprcwb024, ip: [10.120.37.215]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.215"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_scc_internal_03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc_internal_03"
  description  = "role: pr-c-frontend_scc_internal_03, ip: [10.120.37.180]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.180"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_int-api-sports-pds-cmapi-whapi-es-sc1-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_int-api-sports-pds-cmapi-whapi-es-sc1-prod-williamhill-plc"
  description  = "role: pr-c-frontend_int-api-sports-pds-cmapi-whapi-es-sc1-prod-williamhill-plc, ip: [10.121.5.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.5.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_int-api-sports-pds-cmapi-whapi-it-sc1-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_int-api-sports-pds-cmapi-whapi-it-sc1-prod-williamhill-plc"
  description  = "role: pr-c-frontend_int-api-sports-pds-cmapi-whapi-it-sc1-prod-williamhill-plc, ip: [10.121.5.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.5.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprcap45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprcap45"
  description  = "role: pr-c-frontend_sc1uxprcap45, ip: [10.120.50.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.50.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprcap46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprcap46"
  description  = "role: pr-c-frontend_sc1uxprcap46, ip: [10.120.50.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.50.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_tig_cdeproxy-group-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tig_cdeproxy-group-williamhill-plc"
  description  = "role: pr-c-frontend_tig_cdeproxy-group-williamhill-plc, ip: [10.120.44.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_cdeproxy-group-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_cdeproxy-group-williamhill-plc"
  description  = "role: pr-c-frontend_cdeproxy-group-williamhill-plc, ip: [10.120.37.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_scc-backoffice-williamhill-local" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-backoffice-williamhill-local"
  description  = "role: pr-c-frontend_scc-backoffice-williamhill-local, ip: [10.120.38.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.38.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_internalproxy-williamhill-local" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_internalproxy-williamhill-local"
  description  = "role: pr-c-frontend_internalproxy-williamhill-local, ip: [10.120.66.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.66.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_tig-backoffice-williamhill-local" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tig-backoffice-williamhill-local"
  description  = "role: pr-c-frontend_tig-backoffice-williamhill-local, ip: [10.120.74.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.74.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprnap72" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprnap72"
  description  = "role: pr-c-frontend_sc1uxprnap72, ip: [10.120.99.72]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.72"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprnap73" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprnap73"
  description  = "role: pr-c-frontend_sc1uxprnap73, ip: [10.120.99.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.73"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprnap74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprnap74"
  description  = "role: pr-c-frontend_sc1uxprnap74, ip: [10.120.99.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_emailhost03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_emailhost03"
  description  = "role: pr-c-frontend_emailhost03, ip: [10.210.33.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.33.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_emailhost04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_emailhost04"
  description  = "role: pr-c-frontend_emailhost04, ip: [10.210.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_emailhost05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_emailhost05"
  description  = "role: pr-c-frontend_emailhost05, ip: [10.180.33.164]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.33.164"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_emailhost06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_emailhost06"
  description  = "role: pr-c-frontend_emailhost06, ip: [10.180.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn002"
  description  = "role: CHG0123744, ip: [10.120.163.95]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.95"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn003"
  description  = "role: CHG0123744, ip: [10.120.163.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.96"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprgdb05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprgdb05"
  description  = "role: pr-c-frontend_sc1uxprgdb05, ip: [10.120.99.155]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.155"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxprndb531" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxprndb531"
  description  = "role: pr-c-frontend_ld6uxprndb531, ip: [10.118.160.128]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.128"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsux084" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsux084"
  description  = "role: pr-c-frontend_brsux084, ip: [10.1.28.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.133"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnpreap10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnpreap10"
  description  = "role: pr-c-frontend_sc1wnpreap10, ip: [10.120.99.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswntsap10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswntsap10"
  description  = "role: pr-c-frontend_brswntsap10, ip: [10.1.28.87]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.87"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6wnpreap10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6wnpreap10"
  description  = "role: pr-c-frontend_ld6wnpreap10, ip: [10.118.214.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.214.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprewb10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprewb10"
  description  = "role: pr-c-frontend_sc1wnprewb10, ip: [10.120.66.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.66.81"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswntswb10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswntswb10"
  description  = "role: pr-c-frontend_brswntswb10, ip: [10.1.28.88]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.88"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6wnprewb10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6wnprewb10"
  description  = "role: pr-c-frontend_ld6wnprewb10, ip: [10.118.210.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.210.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_irewnprewb10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_irewnprewb10"
  description  = "role: pr-c-frontend_irewnprewb10, ip: [10.120.103.3]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.103.3"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnpredb003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnpredb003"
  description  = "role: pr-c-frontend_sc1wnpredb003, ip: [10.120.65.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.65.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswndredb003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswndredb003"
  description  = "role: pr-c-frontend_brswndredb003, ip: [10.210.65.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.65.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_devjde" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_devjde"
  description  = "role: pr-c-frontend_devjde, ip: [10.120.64.174]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.64.174"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_scc-prodjde" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-prodjde"
  description  = "role: pr-c-frontend_scc-prodjde, ip: [10.120.64.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.64.140"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_int-lb-qlikview" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_int-lb-qlikview"
  description  = "role: pr-c-frontend_int-lb-qlikview, ip: [10.120.74.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.74.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswndvncp003" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswndvncp003"
  description  = "role: pr-c-frontend_brswndvncp003, ip: [10.209.32.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.209.32.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsuxprsap01-brs-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsuxprsap01-brs-prod-williamhill-plc"
  description  = "role: pr-c-frontend_brsuxprsap01-brs-prod-williamhill-plc, ip: [10.210.65.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.65.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprsap01-sc1-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprsap01-sc1-prod-williamhill-plc"
  description  = "role: CHG0125209, ip: [10.120.65.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.65.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprefs03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprefs03"
  description  = "role: pr-c-frontend_sc1wnprefs03, ip: [10.120.194.53]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.53"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprefs03-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprefs03-new"
  description  = "role: pr-c-frontend_sc1wnprefs03-new, ip: [10.120.192.162]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.162"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_scc-int-lb-cde-stingray01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-int-lb-cde-stingray01"
  description  = "role: pr-c-frontend_scc-int-lb-cde-stingray01, ip: [10.120.44.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_scc-int-lb-cde-stingray02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-int-lb-cde-stingray02"
  description  = "role: pr-c-frontend_scc-int-lb-cde-stingray02, ip: [10.120.44.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprcwb41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprcwb41"
  description  = "role: pr-c-frontend_sc1uxprcwb41, ip: [10.120.37.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprcwb42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprcwb42"
  description  = "role: pr-c-frontend_sc1uxprcwb42, ip: [10.120.37.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprcwb41-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprcwb41-new"
  description  = "role: CHG0146120, ip: [10.120.33.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprcwb42-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprcwb42-new"
  description  = "role: CHG0146120, ip: [10.120.33.6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.6"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpreap237_ip_10-120-163-237" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpreap237_ip_10-120-163-237"
  description  = "role: pr-c-frontend_sc1uxpreap237_ip_10-120-163-237, ip: [10.120.163.237]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.237"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpreap238_ip_10-120-163-238" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpreap238_ip_10-120-163-238"
  description  = "role: pr-c-frontend_sc1uxpreap238_ip_10-120-163-238, ip: [10.120.163.238]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.238"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpreap239_ip_10-120-163-239" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpreap239_ip_10-120-163-239"
  description  = "role: pr-c-frontend_sc1uxpreap239_ip_10-120-163-239, ip: [10.120.163.239]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.239"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_aws-central-product-prod-1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_aws-central-product-prod-1"
  description  = "role: CHG0143705, ip: [100.76.144.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.76.144.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_aws-central-product-prod-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_aws-central-product-prod-2"
  description  = "role: CHG0143705, ip: [100.76.146.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.76.146.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_aws-central-product-prod-3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_aws-central-product-prod-3"
  description  = "role: CHG0143705, ip: [100.76.148.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.76.148.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsuxprbkms01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsuxprbkms01-prod-williamhill-plc"
  description  = "role: CHG0136121, ip: [10.210.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsuxprbkms02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsuxprbkms02-prod-williamhill-plc"
  description  = "role: CHG0136121, ip: [10.210.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsuxprbkms03-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsuxprbkms03-prod-williamhill-plc"
  description  = "role: CHG0136121, ip: [10.210.46.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.46.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprbkvs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprbkvs01"
  description  = "role: pr-c-frontend_sc1uxprbkvs01, ip: [10.120.46.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprbkvs02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprbkvs02"
  description  = "role: pr-c-frontend_sc1uxprbkvs02, ip: [10.120.46.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprbkvs03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprbkvs03"
  description  = "role: pr-c-frontend_sc1uxprbkvs03, ip: [10.120.46.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprbkvs04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprbkvs04"
  description  = "role: pr-c-frontend_sc1uxprbkvs04, ip: [10.120.46.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprbkvs05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprbkvs05"
  description  = "role: pr-c-frontend_sc1uxprbkvs05, ip: [10.120.46.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6prapvc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6prapvc01"
  description  = "role: pr-c-frontend_ld6prapvc01, ip: [10.112.8.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.8.253"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprbkms01"
  description  = "role: pr-c-frontend_sc1uxprbkms01, ip: [10.120.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprbkms02"
  description  = "role: pr-c-frontend_sc1uxprbkms02, ip: [10.120.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_bireports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_bireports"
  description  = "role: pr-c-frontend_bireports, ip: [10.120.149.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.229"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1prcap01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1prcap01-prod-williamhill-plc"
  description  = "role: pr-c-frontend_sc1prcap01-prod-williamhill-plc, ip: [10.120.46.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_isilon-cluster-gib" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_isilon-cluster-gib"
  description  = "role: pr-c-frontend_isilon-cluster-gib, ip: [10.180.46.10, 10.180.46.11, 10.180.46.12, 10.180.46.13, 10.180.46.14, 10.180.46.15, 10.180.46.16, 10.180.46.17, 10.180.46.18, 10.180.46.19, 10.180.46.20, 10.180.46.21, 10.180.46.22, 10.180.46.23, 10.180.46.24, 10.180.46.25, 10.180.46.26, 10.180.46.27, 10.180.46.28, 10.180.46.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.10", "10.180.46.11", "10.180.46.12", "10.180.46.13", "10.180.46.14", "10.180.46.15", "10.180.46.16", "10.180.46.17", "10.180.46.18", "10.180.46.19", "10.180.46.20", "10.180.46.21", "10.180.46.22", "10.180.46.23", "10.180.46.24", "10.180.46.25", "10.180.46.26", "10.180.46.27", "10.180.46.28", "10.180.46.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_isilon-cluster-ld6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_isilon-cluster-ld6"
  description  = "role: pr-c-frontend_isilon-cluster-ld6, ip: [10.112.46.10, 10.112.46.11, 10.112.46.12, 10.112.46.13, 10.112.46.14, 10.112.46.15, 10.112.46.16, 10.112.46.17, 10.112.46.18, 10.112.46.19, 10.112.46.20, 10.112.46.21, 10.112.46.22, 10.112.46.23, 10.112.46.24, 10.112.46.25, 10.112.46.26, 10.112.46.27, 10.112.46.28, 10.112.46.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.10", "10.112.46.11", "10.112.46.12", "10.112.46.13", "10.112.46.14", "10.112.46.15", "10.112.46.16", "10.112.46.17", "10.112.46.18", "10.112.46.19", "10.112.46.20", "10.112.46.21", "10.112.46.22", "10.112.46.23", "10.112.46.24", "10.112.46.25", "10.112.46.26", "10.112.46.27", "10.112.46.28", "10.112.46.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gamingdb-mgmt-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gamingdb-mgmt-prod-williamhill-plc"
  description  = "role: pr-c-frontend_gamingdb-mgmt-prod-williamhill-plc, ip: [10.180.146.220]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.146.220"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibux531-mgmt-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibux531-mgmt-prod-williamhill-plc"
  description  = "role: pr-c-frontend_gibux531-mgmt-prod-williamhill-plc, ip: [10.180.146.241]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.146.241"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibux532-mgmt-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibux532-mgmt-prod-williamhill-plc"
  description  = "role: pr-c-frontend_gibux532-mgmt-prod-williamhill-plc, ip: [10.180.146.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.146.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_spbkdb-mgmt-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_spbkdb-mgmt-prod-williamhill-plc"
  description  = "role: pr-c-frontend_spbkdb-mgmt-prod-williamhill-plc, ip: [10.180.146.222]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.146.222"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxd03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxd03"
  description  = "role: pr-c-frontend_sc1uxd03, ip: [10.120.48.111]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.48.111"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxd04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxd04"
  description  = "role: pr-c-frontend_sc1uxd04, ip: [10.120.48.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.48.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_prod"
  description  = "role: pr-c-frontend_prod, ip: [10.1.27.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.27.250"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wncpgap11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wncpgap11"
  description  = "role: pr-c-frontend_sc1wncpgap11, ip: [10.120.99.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprgap03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprgap03"
  description  = "role: pr-c-frontend_sc1wnprgap03, ip: [10.120.99.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprgdb02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprgdb02"
  description  = "role: pr-c-frontend_sc1wnprgdb02, ip: [10.120.99.223]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.223"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_stj-accu-01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_stj-accu-01"
  description  = "role: pr-c-frontend_stj-accu-01, ip: [10.100.4.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.100.4.68"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_stjux049" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_stjux049"
  description  = "role: pr-c-frontend_stjux049, ip: [10.100.50.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.100.50.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wncpgap12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wncpgap12"
  description  = "role: pr-c-frontend_sc1wncpgap12, ip: [10.120.99.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_prod1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_prod1"
  description  = "role: pr-c-frontend_prod1, ip: [10.120.64.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.64.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_prod1_dr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_prod1_dr"
  description  = "role: pr-c-frontend_prod1_dr, ip: [10.210.64.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.64.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprcdb03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprcdb03"
  description  = "role: pr-c-frontend_sc1uxprcdb03, ip: [10.120.52.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.52.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxprcdb04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxprcdb04"
  description  = "role: pr-c-frontend_sc1uxprcdb04, ip: [10.120.52.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.52.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-46-40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-46-40"
  description  = "role: pr-c-frontend_10-120-46-40, ip: [10.120.46.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.40"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-46-41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-46-41"
  description  = "role: pr-c-frontend_10-120-46-41, ip: [10.120.46.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-46-42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-46-42"
  description  = "role: pr-c-frontend_10-120-46-42, ip: [10.120.46.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_paragon-crisantaverbo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_paragon-crisantaverbo"
  description  = "role: CHG0022234, ip: [172.18.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.18.33.165"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_paragon-ellezarmarcelo" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_paragon-ellezarmarcelo"
  description  = "role: CHG0022234, ip: [172.18.32.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.18.32.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_paragon-jeanbuenaventura" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_paragon-jeanbuenaventura"
  description  = "role: CHG0022234, ip: [172.18.32.57]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.18.32.57"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_paragon-mariegracedioniso" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_paragon-mariegracedioniso"
  description  = "role: CHG0022234, ip: [172.18.33.78]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.18.33.78"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_paragon-reggiealtarejos" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_paragon-reggiealtarejos"
  description  = "role: CHG0022234, ip: [172.18.32.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.18.32.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_paragon-rommeltomas" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_paragon-rommeltomas"
  description  = "role: CHG0022234, ip: [172.18.33.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.18.33.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_paragon-waylansebastian" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_paragon-waylansebastian"
  description  = "role: CHG0022234, ip: [172.18.33.85]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.18.33.85"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_trg-manilla-16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_trg-manilla-16"
  description  = "role: pr-c-frontend_trg-manilla-16, ip: [10.123.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_telaviv-172-18-0-0-22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_telaviv-172-18-0-0-22"
  description  = "role: CHG0022234, ip: [172.18.0.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.18.0.0/22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_vpn-gib-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_vpn-gib-24"
  description  = "role: CHG0022234, ip: [192.168.201.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.201.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_openbet-dr-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_openbet-dr-24"
  description  = "role: pr-c-frontend_openbet-dr-24, ip: [10.193.30.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.193.30.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_openbet-live-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_openbet-live-24"
  description  = "role: pr-c-frontend_openbet-live-24, ip: [10.194.20.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.194.20.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_cdebackoffice-williamhill-local" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_cdebackoffice-williamhill-local"
  description  = "role: pr-c-frontend_cdebackoffice-williamhill-local, ip: [10.120.38.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.38.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brs-checkpoint-vpn-ra" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brs-checkpoint-vpn-ra"
  description  = "role: pr-c-frontend_brs-checkpoint-vpn-ra, ip: [192.168.2.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.2.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_lcw-net-10-1-82-0_23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_lcw-net-10-1-82-0_23"
  description  = "role: pr-c-frontend_lcw-net-10-1-82-0_23, ip: [10.1.82.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_lcw-net-10-1-86-0_23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_lcw-net-10-1-86-0_23"
  description  = "role: pr-c-frontend_lcw-net-10-1-86-0_23, ip: [10.1.86.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.86.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_stj-net-10-1-74-0_24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_stj-net-10-1-74-0_24"
  description  = "role: pr-c-frontend_stj-net-10-1-74-0_24, ip: [10.1.74.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.74.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_krk-eoc-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_krk-eoc-lan"
  description  = "role: pr-c-frontend_krk-eoc-lan, ip: [10.55.14.0/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.0/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_krk-eoc-wifi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_krk-eoc-wifi"
  description  = "role: pr-c-frontend_krk-eoc-wifi, ip: [10.55.226.0/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.0/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-55-12-74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-55-12-74"
  description  = "role: pr-c-frontend_10-55-12-74, ip: [10.55.12.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.12.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-55-14-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-55-14-18"
  description  = "role: pr-c-frontend_10-55-14-18, ip: [10.55.14.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-55-14-19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-55-14-19"
  description  = "role: pr-c-frontend_10-55-14-19, ip: [10.55.14.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-55-14-20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-55-14-20"
  description  = "role: pr-c-frontend_10-55-14-20, ip: [10.55.14.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-55-14-22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-55-14-22"
  description  = "role: pr-c-frontend_10-55-14-22, ip: [10.55.14.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.14.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-55-226-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-55-226-18"
  description  = "role: pr-c-frontend_10-55-226-18, ip: [10.55.226.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-55-226-19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-55-226-19"
  description  = "role: pr-c-frontend_10-55-226-19, ip: [10.55.226.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-55-226-20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-55-226-20"
  description  = "role: pr-c-frontend_10-55-226-20, ip: [10.55.226.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-55-226-62" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-55-226-62"
  description  = "role: pr-c-frontend_10-55-226-62, ip: [10.55.226.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.62"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-55-226-74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-55-226-74"
  description  = "role: pr-c-frontend_10-55-226-74, ip: [10.55.226.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.226.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_net_10-55-60-0_28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_net_10-55-60-0_28"
  description  = "role: pr-c-frontend_net_10-55-60-0_28, ip: [10.55.60.0/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.60.0/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_classb-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_classb-12"
  description  = "role: CHG0018964, ip: [172.16.0.0/12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.16.0.0/12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_classc-16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_classc-16"
  description  = "role: CHG0018964, ip: [192.168.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_lcw-robrussell" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_lcw-robrussell"
  description  = "role: pr-c-frontend_lcw-robrussell, ip: [10.1.82.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-121-5-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-121-5-0slash24"
  description  = "role: pr-c-frontend_10-121-5-0slash24, ip: [10.121.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_net-inv-cde-api-lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_net-inv-cde-api-lan"
  description  = "role: CHG0071475, ip: [10.122.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.122.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_wh0004371" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_wh0004371"
  description  = "role: pr-c-frontend_wh0004371, ip: [10.1.83.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.5"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_test-prod-williamhill" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_test-prod-williamhill"
  description  = "role: pr-c-frontend_test-prod-williamhill, ip: [10.1.82.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-83-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-83-11"
  description  = "role: pr-c-frontend_10-1-83-11, ip: [10.1.83.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-53-32-107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-53-32-107"
  description  = "role: pr-c-frontend_10-53-32-107, ip: [10.53.32.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-53-32-93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-53-32-93"
  description  = "role: pr-c-frontend_10-53-32-93, ip: [10.53.32.93]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.93"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-53-33-120" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-53-33-120"
  description  = "role: pr-c-frontend_10-53-33-120, ip: [10.53.32.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.120"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-53-33-56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-53-33-56"
  description  = "role: pr-c-frontend_10-53-33-56, ip: [10.53.33.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.33.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-82-184" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-82-184"
  description  = "role: pr-c-frontend_10-1-82-184, ip: [10.1.82.184]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.184"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-82-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-82-24"
  description  = "role: pr-c-frontend_10-1-82-24, ip: [10.1.82.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-83-154" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-83-154"
  description  = "role: pr-c-frontend_10-1-83-154, ip: [10.1.83.154]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.83.154"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprnap024-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprnap024-prod-williamhill-plc"
  description  = "role: pr-c-frontend_sc1wnprnap024-prod-williamhill-plc, ip: [10.120.100.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.70"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_serveroperations-27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_serveroperations-27"
  description  = "role: Server OPS, ip: [10.1.82.160/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.82.160/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsns01"
  description  = "role: pr-c-frontend_brsns01, ip: [10.210.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsns02"
  description  = "role: pr-c-frontend_brsns02, ip: [10.210.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibns01"
  description  = "role: pr-c-frontend_gibns01, ip: [10.180.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibns02"
  description  = "role: pr-c-frontend_gibns02, ip: [10.180.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sccns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sccns01"
  description  = "role: pr-c-frontend_sccns01, ip: [10.120.193.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.235"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sccns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sccns02"
  description  = "role: pr-c-frontend_sccns02, ip: [10.120.193.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.236"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6ns01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6ns01"
  description  = "role: pr-c-frontend_ld6ns01, ip: [10.112.208.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.208.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6ns02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6ns02"
  description  = "role: pr-c-frontend_ld6ns02, ip: [10.112.208.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.208.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brs-dev-test" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brs-dev-test"
  description  = "role: pr-c-frontend_brs-dev-test, ip: [10.209.32.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.209.32.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brs-dev-test-old" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brs-dev-test-old"
  description  = "role: pr-c-frontend_brs-dev-test-old, ip: [10.1.28.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gib-corp-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gib-corp-tier"
  description  = "role: pr-c-frontend_gib-corp-tier, ip: [10.180.24.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.24.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gib-ncde-db-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gib-ncde-db-tier"
  description  = "role: pr-c-frontend_gib-ncde-db-tier, ip: [10.180.98.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.98.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gib-ncde-mgmt-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gib-ncde-mgmt-tier"
  description  = "role: pr-c-frontend_gib-ncde-mgmt-tier, ip: [10.180.146.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.146.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-cde-frontend-hdr-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-cde-frontend-hdr-tier"
  description  = "role: pr-c-frontend_sc1-cde-frontend-hdr-tier, ip: [10.120.48.96/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.48.96/27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-ncde-app-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-ncde-app-tier"
  description  = "role: pr-c-frontend_sc1-ncde-app-tier, ip: [10.120.99.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-ncde-frontend-ods-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-ncde-frontend-ods-tier"
  description  = "role: pr-c-frontend_sc1-ncde-frontend-ods-tier, ip: [10.120.100.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-ncde-mgmt-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-ncde-mgmt-tier"
  description  = "role: pr-c-frontend_sc1-ncde-mgmt-tier, ip: [10.120.146.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-retail-mgmt-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-retail-mgmt-tier"
  description  = "role: pr-c-frontend_sc1-retail-mgmt-tier, ip: [10.120.180.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-ad-tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-ad-tier"
  description  = "role: pr-c-frontend_sc1-ad-tier, ip: [10.120.194.0/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.0/26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-monitoring" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-monitoring"
  description  = "role: pr-c-frontend_sc1-monitoring, ip: [10.120.163.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn74"
  description  = "role: CHG0067511, ip: [10.120.163.74]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.74"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-46-31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-46-31"
  description  = "role: pr-c-frontend_10-120-46-31, ip: [10.120.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_prdxnex01box001-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_prdxnex01box001-prod-williamhill-plc"
  description  = "role: pr-c-frontend_prdxnex01box001-prod-williamhill-plc, ip: [10.121.10.109]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.109"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_prdxnex01box002-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_prdxnex01box002-prod-williamhill-plc"
  description  = "role: pr-c-frontend_prdxnex01box002-prod-williamhill-plc, ip: [10.121.10.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_prdxnex01box003-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_prdxnex01box003-prod-williamhill-plc"
  description  = "role: pr-c-frontend_prdxnex01box003-prod-williamhill-plc, ip: [10.121.10.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.10.115"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxpremn11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxpremn11"
  description  = "role: CHG0122369, ip: [10.112.12.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.110"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn006" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn006"
  description  = "role: pr-c-frontend_sc1uxpremn006, ip: [10.120.163.118]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.118"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_aws-f5-slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_aws-f5-slash24"
  description  = "role: CHG0127113, ip: [10.125.0.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.0.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_aws-irl-f5-slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_aws-irl-f5-slash24"
  description  = "role: pr-c-frontend_aws-irl-f5-slash24, ip: [10.125.4.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.4.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-46-16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-46-16"
  description  = "role: pr-c-frontend_10-120-46-16, ip: [10.120.46.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-46-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-46-17"
  description  = "role: pr-c-frontend_10-120-46-17, ip: [10.120.46.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-46-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-46-18"
  description  = "role: pr-c-frontend_10-120-46-18, ip: [10.120.46.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-46-19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-46-19"
  description  = "role: pr-c-frontend_10-120-46-19, ip: [10.120.46.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.19"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_uk-sc1-apic1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_uk-sc1-apic1"
  description  = "role: pr-c-frontend_uk-sc1-apic1, ip: [10.120.129.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_uk-sc1-apic2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_uk-sc1-apic2"
  description  = "role: pr-c-frontend_uk-sc1-apic2, ip: [10.120.129.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_uk-sc1-apic3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_uk-sc1-apic3"
  description  = "role: pr-c-frontend_uk-sc1-apic3, ip: [10.120.129.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-38-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-38-11"
  description  = "role: pr-c-frontend_10-120-38-11, ip: [10.120.38.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.38.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-38-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-38-12"
  description  = "role: pr-c-frontend_10-120-38-12, ip: [10.120.38.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.38.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-38-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-38-13"
  description  = "role: pr-c-frontend_10-120-38-13, ip: [10.120.38.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.38.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_cdeproxy-williamhill-remote" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_cdeproxy-williamhill-remote"
  description  = "role: pr-c-frontend_cdeproxy-williamhill-remote, ip: [10.180.42.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.42.80"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_vmc-retail-test" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_vmc-retail-test"
  description  = "role: CHG0145216, ip: [10.233.9.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.233.9.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_bfawnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_bfawnpredc01"
  description  = "role: pr-c-frontend_bfawnpredc01, ip: [10.56.9.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.56.9.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswnpredc01"
  description  = "role: CHG0138309, ip: [10.210.194.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswnpredc02_ip_10-210-194-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswnpredc02_ip_10-210-194-12"
  description  = "role: CHG0141790, ip: [10.210.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswnpredc03-chg0144834" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswnpredc03-chg0144834"
  description  = "role: CHG0144834, ip: [10.210.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibwnpredc02_ip_10-180-194-12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibwnpredc02_ip_10-180-194-12"
  description  = "role: CHG0141790, ip: [10.180.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibwnpredc03_ip_10-180-194-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibwnpredc03_ip_10-180-194-13"
  description  = "role: CHG0141790, ip: [10.180.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_irewnprdc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_irewnprdc01"
  description  = "role: CHG0141790, ip: [100.72.225.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.225.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_irewnprdc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_irewnprdc02"
  description  = "role: CHG0141790, ip: [100.72.225.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.225.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_nvawnprdc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_nvawnprdc01"
  description  = "role: CHG0144834, ip: [100.97.1.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.97.1.135"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_nvawnprdc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_nvawnprdc02"
  description  = "role: CHG0144834, ip: [100.97.1.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.97.1.167"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_krawnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_krawnpredc01"
  description  = "role: pr-c-frontend_krawnpredc01, ip: [10.55.9.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.9.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_krawnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_krawnpredc02"
  description  = "role: pr-c-frontend_krawnpredc02, ip: [10.55.9.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.55.9.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6wnpredc01-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6wnpredc01-new"
  description  = "role: pr-c-frontend_ld6wnpredc01-new, ip: [10.19.2.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.21"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6wnpredc02-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6wnpredc02-new"
  description  = "role: pr-c-frontend_ld6wnpredc02-new, ip: [10.19.2.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_mnlwnpredc02_ip_10-123-197-11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_mnlwnpredc02_ip_10-123-197-11"
  description  = "role: CHG0141790, ip: [10.123.197.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.197.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_mnlwnpredc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_mnlwnpredc03"
  description  = "role: pr-c-frontend_mnlwnpredc03, ip: [10.123.197.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.197.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnpredc01"
  description  = "role: CHG0138309, ip: [10.120.194.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnpredc02"
  description  = "role: CHG0138309, ip: [10.120.194.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnpredc03_ip_10-120-194-13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnpredc03_ip_10-120-194-13"
  description  = "role: CHG0141790, ip: [10.120.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnpredc04_ip_10-120-194-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnpredc04_ip_10-120-194-14"
  description  = "role: CHG0141790, ip: [10.120.194.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnpredc05_ip_10-120-194-15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnpredc05_ip_10-120-194-15"
  description  = "role: CHG0141790, ip: [10.120.194.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnpredc08_ip_10-120-194-18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnpredc08_ip_10-120-194-18"
  description  = "role: CHG0141790, ip: [10.120.194.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sofwnpredc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sofwnpredc01"
  description  = "role: pr-c-frontend_sofwnpredc01, ip: [10.53.98.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.98.10"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sofwnpredc02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sofwnpredc02"
  description  = "role: pr-c-frontend_sofwnpredc02, ip: [10.53.98.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.98.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsapprcmg002-group-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsapprcmg002-group-williamhill-plc"
  description  = "role: CHG0142765, ip: [10.210.163.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpreap242" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpreap242"
  description  = "role: pr-c-frontend_sc1uxpreap242, ip: [10.120.163.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxrdk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxrdk"
  description  = "role: pr-c-frontend_sc1uxrdk, ip: [10.120.163.131]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.131"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsux910" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsux910"
  description  = "role: pr-c-frontend_brsux910, ip: [10.1.28.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.28.4"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibux910" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibux910"
  description  = "role: pr-c-frontend_gibux910, ip: [10.180.163.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxpreds01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxpreds01"
  description  = "role: pr-c-frontend_ld6uxpreds01, ip: [10.112.12.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpreds01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpreds01"
  description  = "role: pr-c-frontend_sc1uxpreds01, ip: [10.120.194.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxstnmg01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxstnmg01"
  description  = "role: pr-c-frontend_sc1uxstnmg01, ip: [10.120.163.130]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.130"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsuxkat" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsuxkat"
  description  = "role: pr-c-frontend_brsuxkat, ip: [10.210.163.130]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.130"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibuxkat" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibuxkat"
  description  = "role: pr-c-frontend_gibuxkat, ip: [10.180.163.130]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.130"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswsus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswsus"
  description  = "role: pr-c-frontend_brswsus, ip: [10.210.163.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibwsus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibwsus"
  description  = "role: pr-c-frontend_gibwsus, ip: [10.180.163.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_stjwsus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_stjwsus"
  description  = "role: pr-c-frontend_stjwsus, ip: [10.110.163.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.110.163.114"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibux-hf1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibux-hf1"
  description  = "role: pr-c-frontend_gibux-hf1, ip: [10.180.163.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibux-indx1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibux-indx1"
  description  = "role: pr-c-frontend_gibux-indx1, ip: [10.180.163.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibux-indx2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibux-indx2"
  description  = "role: pr-c-frontend_gibux-indx2, ip: [10.180.163.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibuxpremn01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibuxpremn01"
  description  = "role: pr-c-frontend_gibuxpremn01, ip: [10.180.163.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.22"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibuxpremn03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibuxpremn03"
  description  = "role: pr-c-frontend_gibuxpremn03, ip: [10.180.163.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibuxpremn04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibuxpremn04"
  description  = "role: pr-c-frontend_gibuxpremn04, ip: [10.180.163.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.163.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpromn012" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpromn012"
  description  = "role: pr-c-frontend_sc1uxpromn012, ip: [10.120.163.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-121-7-0slash24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-121-7-0slash24"
  description  = "role: pr-c-frontend_10-121-7-0slash24, ip: [10.121.7.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.7.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsuxpremn65" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsuxpremn65"
  description  = "role: CHG0079749, ip: [10.210.163.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsuxpremn66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsuxpremn66"
  description  = "role: CHG0079749, ip: [10.210.163.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn65" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn65"
  description  = "role: CHG0079749, ip: [10.120.163.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.65"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn66"
  description  = "role: CHG0079749, ip: [10.120.163.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.66"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxpremn13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxpremn13"
  description  = "role: pr-c-frontend_ld6uxpremn13, ip: [10.112.12.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.12.112"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswndremg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswndremg002"
  description  = "role: pr-c-frontend_brswndremg002, ip: [10.210.194.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnpremg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnpremg002"
  description  = "role: pr-c-frontend_sc1wnpremg002, ip: [10.120.194.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.52"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1appresc02-data" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1appresc02-data"
  description  = "role: CHG0122435, ip: [10.120.163.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1appresc03-data" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1appresc03-data"
  description  = "role: CHG0122435, ip: [10.120.163.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.152"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb01-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb01-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb02-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb02-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb03-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb03-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb04-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb04-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.184]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.184"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb09-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb09-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb10-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb10-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb11-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb11-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb12-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb12-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb005-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb005-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.196]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.196"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb006-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb006-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.197]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.197"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb007-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb007-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb008-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb008-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.199"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb013-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb013-prod-williamhill-plc"
  description  = "role: pr-c-frontend_sc1apprcwb013-prod-williamhill-plc, ip: [10.120.37.204]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.204"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb014-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb014-prod-williamhill-plc"
  description  = "role: pr-c-frontend_sc1apprcwb014-prod-williamhill-plc, ip: [10.120.37.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.205"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb016-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb016-prod-williamhill-plc"
  description  = "role: pr-c-frontend_sc1apprcwb016-prod-williamhill-plc, ip: [10.120.37.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.207"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb015-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb015-prod-williamhill-plc"
  description  = "role: pr-c-frontend_sc1apprcwb015-prod-williamhill-plc, ip: [10.120.37.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.206"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb017-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb017-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.208"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb018-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb018-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.209]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.209"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb019-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb019-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.210"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb020-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb020-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb021-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb021-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb022-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb022-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb023-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb023-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb024-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb024-prod-williamhill-plc"
  description  = "role: CHG0144060, ip: [10.120.37.215]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.215"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb01"
  description  = "role: pr-c-frontend_sc1apprcwb01, ip: [10.120.37.181]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.181"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb02"
  description  = "role: pr-c-frontend_sc1apprcwb02, ip: [10.120.37.182]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.182"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb03"
  description  = "role: pr-c-frontend_sc1apprcwb03, ip: [10.120.37.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.183"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb04"
  description  = "role: pr-c-frontend_sc1apprcwb04, ip: [10.120.37.184]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.184"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb005" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb005"
  description  = "role: pr-c-frontend_sc1apprcwb005, ip: [10.120.37.196]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.196"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb006" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb006"
  description  = "role: pr-c-frontend_sc1apprcwb006, ip: [10.120.37.197]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.197"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb007" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb007"
  description  = "role: pr-c-frontend_sc1apprcwb007, ip: [10.120.37.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.198"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb008" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb008"
  description  = "role: pr-c-frontend_sc1apprcwb008, ip: [10.120.37.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.199"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb009-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb009-prod-williamhill-plc"
  description  = "role: pr-c-frontend_sc1apprcwb009-prod-williamhill-plc, ip: [10.120.37.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.200"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb010-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb010-prod-williamhill-plc"
  description  = "role: pr-c-frontend_sc1apprcwb010-prod-williamhill-plc, ip: [10.120.37.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.201"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb011-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb011-prod-williamhill-plc"
  description  = "role: pr-c-frontend_sc1apprcwb011-prod-williamhill-plc, ip: [10.120.37.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.202"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1apprcwb012-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1apprcwb012-prod-williamhill-plc"
  description  = "role: pr-c-frontend_sc1apprcwb012-prod-williamhill-plc, ip: [10.120.37.203]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.203"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_puppet-ncx-scc-ca-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_puppet-ncx-scc-ca-prod-williamhill-plc"
  description  = "role: pr-c-frontend_puppet-ncx-scc-ca-prod-williamhill-plc, ip: [10.120.44.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_puppet-ncx-scc-db-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_puppet-ncx-scc-db-prod-williamhill-plc"
  description  = "role: pr-c-frontend_puppet-ncx-scc-db-prod-williamhill-plc, ip: [10.120.44.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_puppet-ncx-scc-prod-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_puppet-ncx-scc-prod-williamhill-plc"
  description  = "role: pr-c-frontend_puppet-ncx-scc-prod-williamhill-plc, ip: [10.120.44.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxprbkms01"
  description  = "role: pr-c-frontend_ld6uxprbkms01, ip: [10.112.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxprbkms02"
  description  = "role: pr-c-frontend_ld6uxprbkms02, ip: [10.112.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxprbkms03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxprbkms03"
  description  = "role: pr-c-frontend_ld6uxprbkms03, ip: [10.112.46.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxprbkms04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxprbkms04"
  description  = "role: pr-c-frontend_ld6uxprbkms04, ip: [10.112.46.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibuxprbkms01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibuxprbkms01"
  description  = "role: pr-c-frontend_gibuxprbkms01, ip: [10.180.46.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_gibuxprbkms02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_gibuxprbkms02"
  description  = "role: pr-c-frontend_gibuxprbkms02, ip: [10.180.46.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.46.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6wnprbkcs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6wnprbkcs01"
  description  = "role: CHG0112231, ip: [10.112.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxprbkvs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxprbkvs01"
  description  = "role: pr-c-frontend_ld6uxprbkvs01, ip: [10.112.46.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.35"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxprbkvs02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxprbkvs02"
  description  = "role: pr-c-frontend_ld6uxprbkvs02, ip: [10.112.46.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.36"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxprbkvs03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxprbkvs03"
  description  = "role: pr-c-frontend_ld6uxprbkvs03, ip: [10.112.46.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxprbkvs04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxprbkvs04"
  description  = "role: pr-c-frontend_ld6uxprbkvs04, ip: [10.112.46.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.38"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_ld6uxprbkvs05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ld6uxprbkvs05"
  description  = "role: pr-c-frontend_ld6uxprbkvs05, ip: [10.112.46.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.39"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsux279_280-p1-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsux279_280-p1-vip"
  description  = "role: CHG0137980, ip: [10.1.29.211]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.211"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsux279_280-p2-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsux279_280-p2-vip"
  description  = "role: CHG0137980, ip: [10.1.29.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.212"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsux279_280-p3-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsux279_280-p3-vip"
  description  = "role: CHG0137980, ip: [10.1.29.213]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.213"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsux279_280-stg-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsux279_280-stg-vip"
  description  = "role: CHG0137980, ip: [10.1.29.222]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.222"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsux279_280-sys-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsux279_280-sys-vip"
  description  = "role: CHG0137980, ip: [10.1.29.221]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.221"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brsux279_280-tem-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brsux279_280-tem-vip"
  description  = "role: CHG0137980, ip: [10.1.29.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.214"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_wp-4th-data" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_wp-4th-data"
  description  = "role: CHG0019704, ip: [10.180.29.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.29.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_wp-5th-data-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_wp-5th-data-24"
  description  = "role: CHG0019704, ip: [10.180.27.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.27.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_wp-6th-data-23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_wp-6th-data-23"
  description  = "role: pr-c-frontend_wp-6th-data-23, ip: [10.180.18.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.18.0/23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_wp-gnd-data-24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_wp-gnd-data-24"
  description  = "role: CHG0019704, ip: [10.180.20.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.20.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa03"
  description  = "role: CHG0017483, ip: [10.120.39.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.23"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa04"
  description  = "role: CHG0017483, ip: [10.120.39.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa05"
  description  = "role: CHG0017483, ip: [10.120.39.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa06"
  description  = "role: CHG0017483, ip: [10.120.39.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa07" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa07"
  description  = "role: CHG0017483, ip: [10.120.39.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.27"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa08" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa08"
  description  = "role: CHG0017483, ip: [10.120.39.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa09" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa09"
  description  = "role: CHG0017483, ip: [10.120.39.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa10"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa10, ip: [10.120.39.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa11"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa11, ip: [10.120.39.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.31"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa12"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa12, ip: [10.120.39.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.32"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa13"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa13, ip: [10.120.39.33]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.33"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa14"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa14, ip: [10.120.39.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.34"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa01"
  description  = "role: CHG0017483, ip: [10.120.39.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa02"
  description  = "role: CHG0017483, ip: [10.120.39.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa21"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa21, ip: [10.120.39.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.41"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa22"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa22, ip: [10.120.39.42]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.42"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa23"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa23, ip: [10.120.39.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.43"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa24"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa24, ip: [10.120.39.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.44"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa25"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa25, ip: [10.120.39.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.45"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa26"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa26, ip: [10.120.39.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa27"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa27, ip: [10.120.39.47]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.47"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa28"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa28, ip: [10.120.39.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.48"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-xa29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-xa29"
  description  = "role: pr-c-frontend_sc1-wn-pre-xa29, ip: [10.120.39.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.49"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprexa35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprexa35"
  description  = "role: pr-c-frontend_sc1wnprexa35, ip: [10.120.39.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.55"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprexa36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprexa36"
  description  = "role: pr-c-frontend_sc1wnprexa36, ip: [10.120.39.56]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.56"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprexp01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprexp01"
  description  = "role: CHG0018815, ip: [10.120.39.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.51"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprexp100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprexp100"
  description  = "role: CHG0018815, ip: [10.120.39.150]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.150"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprexp95" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprexp95"
  description  = "role: CHG0018815, ip: [10.120.39.145]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.145"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprexp96" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprexp96"
  description  = "role: CHG0018815, ip: [10.120.39.146]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.146"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprexp97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprexp97"
  description  = "role: CHG0018815, ip: [10.120.39.147]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.147"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprexp98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprexp98"
  description  = "role: CHG0018815, ip: [10.120.39.148]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.148"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprexp99" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprexp99"
  description  = "role: CHG0018815, ip: [10.120.39.149]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.149"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1wnprexa151" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1wnprexa151"
  description  = "role: CHG0148435, ip: [10.120.39.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.151"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-39-128-28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-39-128-28"
  description  = "role: pr-c-frontend_10-120-39-128-28, ip: [10.120.39.128/28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.128/28"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-39-144" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-39-144"
  description  = "role: pr-c-frontend_10-120-39-144, ip: [10.120.39.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.144"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-39-52-30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-39-52-30"
  description  = "role: pr-c-frontend_10-120-39-52-30, ip: [10.120.39.52/30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.52/30"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-39-56-29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-39-56-29"
  description  = "role: pr-c-frontend_10-120-39-56-29, ip: [10.120.39.56/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.56/29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-120-39-64-26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-120-39-64-26"
  description  = "role: pr-c-frontend_10-120-39-64-26, ip: [10.120.39.64/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.64/26"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_stj-alan-huner-backup" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_stj-alan-huner-backup"
  description  = "role: pr-c-frontend_stj-alan-huner-backup, ip: [10.1.18.46]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.46"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_stj-alan-hunter" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_stj-alan-hunter"
  description  = "role: pr-c-frontend_stj-alan-hunter, ip: [10.1.18.226]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.18.226"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn105" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn105"
  description  = "role: pr-c-frontend_sc1uxpremn105, ip: [10.120.163.105]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.105"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn106"
  description  = "role: pr-c-frontend_sc1uxpremn106, ip: [10.120.163.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn107"
  description  = "role: pr-c-frontend_sc1uxpremn107, ip: [10.120.163.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn108" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn108"
  description  = "role: pr-c-frontend_sc1uxpremn108, ip: [10.120.163.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.108"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn120" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn120"
  description  = "role: pr-c-frontend_sc1uxpremn120, ip: [10.120.163.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.120"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1uxpremn121" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1uxpremn121"
  description  = "role: pr-c-frontend_sc1uxpremn121, ip: [10.120.163.121]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.121"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-58-100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-58-100"
  description  = "role: pr-c-frontend_10-1-58-100, ip: [10.1.58.100]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.100"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-58-101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-58-101"
  description  = "role: pr-c-frontend_10-1-58-101, ip: [10.1.58.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.101"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-58-102" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-58-102"
  description  = "role: pr-c-frontend_10-1-58-102, ip: [10.1.58.102]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.102"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-58-103" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-58-103"
  description  = "role: pr-c-frontend_10-1-58-103, ip: [10.1.58.103]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.103"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-58-104" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-58-104"
  description  = "role: pr-c-frontend_10-1-58-104, ip: [10.1.58.104]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.104"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-58-97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-58-97"
  description  = "role: pr-c-frontend_10-1-58-97, ip: [10.1.58.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.97"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-58-98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-58-98"
  description  = "role: pr-c-frontend_10-1-58-98, ip: [10.1.58.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.98"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-58-99" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-58-99"
  description  = "role: pr-c-frontend_10-1-58-99, ip: [10.1.58.99]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.99"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-58-106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-58-106"
  description  = "role: CHG0123895, ip: [10.1.58.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.106"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-58-107" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-58-107"
  description  = "role: CHG0123895, ip: [10.1.58.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.107"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_10-1-58-29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_10-1-58-29"
  description  = "role: CHG0123895, ip: [10.1.58.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.58.29"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswn109" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswn109"
  description  = "role: pr-c-frontend_brswn109, ip: [10.1.29.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.29.37"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_vmc-retail-production-vsphere-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_vmc-retail-production-vsphere-mgmt"
  description  = "role: pr-c-frontend_vmc-retail-production-vsphere-mgmt, ip: [10.126.32.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.32.0/20"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_vmc-retail-production-10-233-0-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_vmc-retail-production-10-233-0-0s24"
  description  = "role: pr-c-frontend_vmc-retail-production-10-233-0-0s24, ip: [10.233.0.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.233.0.0/24"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_vmc-retail-production-services-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_vmc-retail-production-services-mgmt"
  description  = "role: pr-c-frontend_vmc-retail-production-services-mgmt, ip: [10.156.1.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.1.0/25"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-dc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-dc03"
  description  = "role: CHG0017397, ip: [10.120.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-dc04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-dc04"
  description  = "role: CHG0017397, ip: [10.120.194.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.14"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-dc05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-dc05"
  description  = "role: CHG0017397, ip: [10.120.194.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.15"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-dc06" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-dc06"
  description  = "role: CHG0017397, ip: [10.120.194.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.16"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-dc07" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-dc07"
  description  = "role: CHG0017397, ip: [10.120.194.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.17"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_sc1-wn-pre-dc08" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_sc1-wn-pre-dc08"
  description  = "role: CHG0017397, ip: [10.120.194.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.18"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_brswnpredc03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_brswnpredc03"
  description  = "role: pr-c-frontend_brswnpredc03, ip: [10.210.194.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.13"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_svr-cpr-whapi-snat240-vi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_svr-cpr-whapi-snat240-vi"
  description  = "role: pr-c-frontend_svr-cpr-whapi-snat240-vi, ip: [10.120.216.240]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.216.240"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_svr-cpr-whapi-snat242-vi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_svr-cpr-whapi-snat242-vi"
  description  = "role: pr-c-frontend_svr-cpr-whapi-snat242-vi, ip: [10.120.216.242]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.216.242"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_svr-cpr-whapi-snat241-vi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_svr-cpr-whapi-snat241-vi"
  description  = "role: pr-c-frontend_svr-cpr-whapi-snat241-vi, ip: [10.120.216.241]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.216.241"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_svr-f5top01-re" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_svr-f5top01-re"
  description  = "role: pr-c-frontend_svr-f5top01-re, ip: [10.120.216.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.216.11"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_svr-f5top02-re" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_svr-f5top02-re"
  description  = "role: pr-c-frontend_svr-f5top02-re, ip: [10.120.216.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.216.12"]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_svr-f5top03-re" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_svr-f5top03-re"
  description  = "role: pr-c-frontend_svr-f5top03-re, ip: [10.120.216.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.216.10"]
    }
  }
}

/*======================================
#### object-groups ####
========================================*/

resource "nsxt_policy_group" "pr-c-frontend_grp_whapi-gateway-srvs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_whapi-gateway-srvs"
  description  = "role: pr-c-frontend_grp_whapi-gateway-srvs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_scc_internal_01.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb017.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb018.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb019.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb020.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb021.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb022.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb023.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb024.path, nsxt_policy_group.pr-c-frontend_grp_grp-scc-pr-cwb-layer7.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_whapi-gateways" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_whapi-gateways"
  description  = "role: CHG0144060"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_grp_scc-whapi-c1.path, nsxt_policy_group.pr-c-frontend_grp_scc-whapi-c2.path, nsxt_policy_group.pr-c-frontend_grp_scc-whapi-c3.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-scc-pr-cwb-layer7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-scc-pr-cwb-layer7"
  description  = "role: pr-c-frontend_grp_grp-scc-pr-cwb-layer7"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1apprcwb017.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb018.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb019.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb020.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb021.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb022.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb023.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb024.path, nsxt_policy_group.pr-c-frontend_grp_grp-scc-pr-cwb-layer7-top.path, nsxt_policy_group.pr-c-frontend_grp_grp-scc-pr-cwb-layer7new-top.path, nsxt_policy_group.pr-c-frontend_grp_grp-scc-pr-cwb-layer7-top-3.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_outbound-ext-web-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_outbound-ext-web-access"
  description  = "role: pr-c-frontend_grp_outbound-ext-web-access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_net_10-120-37-0m24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_internet-all-subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_internet-all-subnets"
  description  = "role: This is all the networks that make up the internet, less RFC1918 and Class D,E"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_0-0-0-0s5.path, nsxt_policy_group.pr-c-frontend_ip_8-0-0-0s7.path, nsxt_policy_group.pr-c-frontend_ip_11-0-0-0s8.path, nsxt_policy_group.pr-c-frontend_ip_12-0-0-0s6.path, nsxt_policy_group.pr-c-frontend_ip_16-0-0-0s4.path, nsxt_policy_group.pr-c-frontend_ip_32-0-0-0s3.path, nsxt_policy_group.pr-c-frontend_ip_64-0-0-0s2.path, nsxt_policy_group.pr-c-frontend_ip_128-0-0-0s3.path, nsxt_policy_group.pr-c-frontend_ip_160-0-0-0s5.path, nsxt_policy_group.pr-c-frontend_ip_168-0-0-0s6.path, nsxt_policy_group.pr-c-frontend_ip_172-0-0-0s12.path, nsxt_policy_group.pr-c-frontend_ip_172-32-0-0s11.path, nsxt_policy_group.pr-c-frontend_ip_172-64-0-0s10.path, nsxt_policy_group.pr-c-frontend_ip_172-128-0-0s9.path, nsxt_policy_group.pr-c-frontend_ip_173-0-0-0s8.path, nsxt_policy_group.pr-c-frontend_ip_174-0-0-0s7.path, nsxt_policy_group.pr-c-frontend_ip_176-0-0-0s4.path, nsxt_policy_group.pr-c-frontend_ip_192-0-0-0s9.path, nsxt_policy_group.pr-c-frontend_ip_192-128-0-0s11.path, nsxt_policy_group.pr-c-frontend_ip_192-160-0-0s13.path, nsxt_policy_group.pr-c-frontend_ip_192-169-0-0s16.path, nsxt_policy_group.pr-c-frontend_ip_192-170-0-0s15.path, nsxt_policy_group.pr-c-frontend_ip_192-172-0-0s14.path, nsxt_policy_group.pr-c-frontend_ip_192-176-0-0s12.path, nsxt_policy_group.pr-c-frontend_ip_192-192-0-0s10.path, nsxt_policy_group.pr-c-frontend_ip_193-0-0-0s8.path, nsxt_policy_group.pr-c-frontend_ip_194-0-0-0s7.path, nsxt_policy_group.pr-c-frontend_ip_196-0-0-0s6.path, nsxt_policy_group.pr-c-frontend_ip_200-0-0-0s5.path, nsxt_policy_group.pr-c-frontend_ip_208-0-0-0s4.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_outbound-any-web-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_outbound-any-web-access"
  description  = "role: pr-c-frontend_grp_outbound-any-web-access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_scc_internal_03.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb017.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb018.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb019.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb020.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb021.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb022.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb023.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb024.path, nsxt_policy_group.pr-c-frontend_grp_grp-scc-pr-cwb-layer7.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_outbound-3rdparty-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_outbound-3rdparty-access"
  description  = "role: pr-c-frontend_grp_outbound-3rdparty-access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_net_10-120-37-0m24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-sports-pds-cmapi-whapi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-sports-pds-cmapi-whapi"
  description  = "role: pr-c-frontend_grp_scc-sports-pds-cmapi-whapi"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_int-api-sports-pds-cmapi-whapi-es-sc1-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_int-api-sports-pds-cmapi-whapi-it-sc1-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_26"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_26"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_grp_cde_backoffice_app_servers.path, nsxt_policy_group.pr-c-frontend_grp_cde_crypto_app_servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_27"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_27"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_informix-db-vip.path, nsxt_policy_group.pr-c-frontend_informix-hdr-vip.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_50" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_50"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_50"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprcap45.path, nsxt_policy_group.pr-c-frontend_sc1uxprcap46.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_6"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_6"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_tig_cdeproxy-group-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_cdeproxy-group-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_57" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_57"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_57"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprcap45.path, nsxt_policy_group.pr-c-frontend_sc1uxprcap46.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_59" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_59"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_59"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_scc-backoffice-williamhill-local.path, nsxt_policy_group.pr-c-frontend_internalproxy-williamhill-local.path, nsxt_policy_group.pr-c-frontend_int-lb-cdebackoffice-sc1-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_tig-backoffice-williamhill-local.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_cde_backoffice_app_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_cde_backoffice_app_servers"
  description  = "role: pr-c-frontend_grp_cde_backoffice_app_servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprcap45.path, nsxt_policy_group.pr-c-frontend_sc1uxprcap46.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_oxi_application_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_oxi_application_servers"
  description  = "role: pr-c-frontend_grp_oxi_application_servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprnap71.path, nsxt_policy_group.pr-c-frontend_sc1uxprnap72.path, nsxt_policy_group.pr-c-frontend_sc1uxprnap73.path, nsxt_policy_group.pr-c-frontend_sc1uxprnap74.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_146" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_146"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_146"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprcap45.path, nsxt_policy_group.pr-c-frontend_sc1uxprcap46.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_mailhosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_mailhosts"
  description  = "role: pr-c-frontend_grp_mailhosts"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_emailhost01.path, nsxt_policy_group.pr-c-frontend_emailhost02.path, nsxt_policy_group.pr-c-frontend_emailhost03.path, nsxt_policy_group.pr-c-frontend_emailhost04.path, nsxt_policy_group.pr-c-frontend_emailhost05.path, nsxt_policy_group.pr-c-frontend_emailhost06.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_116" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_116"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_116"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_emailhost01.path, nsxt_policy_group.pr-c-frontend_emailhost02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_splunk-group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_splunk-group"
  description  = "role: CHG0123744"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxpremn002.path, nsxt_policy_group.pr-c-frontend_sc1uxpremn003.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-dr-oracle-db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-dr-oracle-db"
  description  = "role: pr-c-frontend_grp_grp-dr-oracle-db"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprgdb05.path, nsxt_policy_group.pr-c-frontend_ld6uxprndb531.path, nsxt_policy_group.pr-c-frontend_brsux084.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-dr-noncde-citrix-dvs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-dr-noncde-citrix-dvs"
  description  = "role: pr-c-frontend_grp_grp-dr-noncde-citrix-dvs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-noncde-citrix-dvs-onshore.path, nsxt_policy_group.pr-c-frontend_grp_grp-dr-noncde-citrix-dvs-offshore.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-dr-noncde-accurate-batch-srvs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-dr-noncde-accurate-batch-srvs"
  description  = "role: pr-c-frontend_grp_grp-dr-noncde-accurate-batch-srvs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1wnpreap10.path, nsxt_policy_group.pr-c-frontend_brswntsap10.path, nsxt_policy_group.pr-c-frontend_ld6wnpreap10.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-dr-noncde-accurate-web-srvs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-dr-noncde-accurate-web-srvs"
  description  = "role: pr-c-frontend_grp_grp-dr-noncde-accurate-web-srvs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1wnprewb10.path, nsxt_policy_group.pr-c-frontend_brswntswb10.path, nsxt_policy_group.pr-c-frontend_ld6wnprewb10.path, nsxt_policy_group.pr-c-frontend_irewnprewb10.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-dr-noncde-propman-db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-dr-noncde-propman-db"
  description  = "role: pr-c-frontend_grp_grp-dr-noncde-propman-db"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1wnpredb003.path, nsxt_policy_group.pr-c-frontend_brswndredb003.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-dr-noncde-tanda-svr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-dr-noncde-tanda-svr"
  description  = "role: pr-c-frontend_grp_grp-dr-noncde-tanda-svr"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-146-115.path, nsxt_policy_group.pr-c-frontend_ip_10-120-146-116.path, nsxt_policy_group.pr-c-frontend_ip_10-210-146-206.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-dr-jde-svr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-dr-jde-svr"
  description  = "role: pr-c-frontend_grp_grp-dr-jde-svr"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_devjde.path, nsxt_policy_group.pr-c-frontend_scc-prodjde.path, nsxt_policy_group.pr-c-frontend_ip_10-120-64-152.path, nsxt_policy_group.pr-c-frontend_ip_10-210-64-152.path, nsxt_policy_group.pr-c-frontend_ip_10-210-64-140.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-dr-jde-app-svr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-dr-jde-app-svr"
  description  = "role: pr-c-frontend_grp_grp-dr-jde-app-svr"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-210-64-142.path, nsxt_policy_group.pr-c-frontend_ip_10-210-64-147.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-dr-noncde-citrix-dvs-onshore" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-dr-noncde-citrix-dvs-onshore"
  description  = "role: pr-c-frontend_grp_grp-dr-noncde-citrix-dvs-onshore"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-39-143.path, nsxt_policy_group.pr-c-frontend_ip_10-120-39-142.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-dr-noncde-qlikview-web" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-dr-noncde-qlikview-web"
  description  = "role: pr-c-frontend_grp_grp-dr-noncde-qlikview-web"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_int-lb-qlikview.path, nsxt_policy_group.pr-c-frontend_brswndvncp003.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-dr-noncde-sap-routers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-dr-noncde-sap-routers"
  description  = "role: pr-c-frontend_grp_grp-dr-noncde-sap-routers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brsuxprsap01-brs-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1uxprsap01-sc1-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-dr-noncde-citrix-dvs-offshore" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-dr-noncde-citrix-dvs-offshore"
  description  = "role: pr-c-frontend_grp_grp-dr-noncde-citrix-dvs-offshore"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-39-147.path, nsxt_policy_group.pr-c-frontend_ip_10-120-39-148.path, nsxt_policy_group.pr-c-frontend_sc1wnprexp99.path, nsxt_policy_group.pr-c-frontend_sc1wnprexp100.path, nsxt_policy_group.pr-c-frontend_sc1wnprexa151.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_148" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_148"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_148"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1wnprefs03.path, nsxt_policy_group.pr-c-frontend_sc1wnprefs03-new.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_149" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_149"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_149"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1wnprefs03.path, nsxt_policy_group.pr-c-frontend_sc1wnprefs03-new.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_4"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_4"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_scc-int-lb-cde-stingray01.path, nsxt_policy_group.pr-c-frontend_scc-int-lb-cde-stingray02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_8"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_8"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprcwb41.path, nsxt_policy_group.pr-c-frontend_sc1uxprcwb42.path, nsxt_policy_group.pr-c-frontend_sc1uxprcwb41-new.path, nsxt_policy_group.pr-c-frontend_sc1uxprcwb42-new.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-scc-int-lb-cde-stingray" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-scc-int-lb-cde-stingray"
  description  = "role: pr-c-frontend_grp_grp-scc-int-lb-cde-stingray"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_scc-int-lb-cde-stingray01.path, nsxt_policy_group.pr-c-frontend_scc-int-lb-cde-stingray02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-brocade-svc-control" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-brocade-svc-control"
  description  = "role: pr-c-frontend_grp_grp-brocade-svc-control"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-163-140.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-140.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-145.path, nsxt_policy_group.pr-c-frontend_ip_10-210-163-20.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_15"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_15"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_scc-int-lb-cde-stingray01.path, nsxt_policy_group.pr-c-frontend_scc-int-lb-cde-stingray02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_22"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_22"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path, nsxt_policy_group.pr-c-frontend_sc1-whapi-servers.path, nsxt_policy_group.pr-c-frontend_ip_10-120-33-160s27.path, nsxt_policy_group.pr-c-frontend_ip_10-120-38-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-33-0s29.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_30"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_30"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_scc-int-lb-cde-stingray01.path, nsxt_policy_group.pr-c-frontend_scc-int-lb-cde-stingray02.path, nsxt_policy_group.pr-c-frontend_grp_puppet-ncx-servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_25"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_25"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-163-97.path, nsxt_policy_group.pr-c-frontend_ip_10-120-163-98.path, nsxt_policy_group.pr-c-frontend_grp_scc-management-subnets.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_rundeck-application-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_rundeck-application-servers"
  description  = "role: pr-c-frontend_grp_rundeck-application-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxpreap237_ip_10-120-163-237.path, nsxt_policy_group.pr-c-frontend_sc1uxpreap238_ip_10-120-163-238.path, nsxt_policy_group.pr-c-frontend_sc1uxpreap239_ip_10-120-163-239.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_aws-central-product-prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_aws-central-product-prod"
  description  = "role: CHG0143705"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_aws-central-product-prod-1.path, nsxt_policy_group.pr-c-frontend_aws-central-product-prod-2.path, nsxt_policy_group.pr-c-frontend_aws-central-product-prod-3.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_commvault-brs-media-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_commvault-brs-media-servers"
  description  = "role: CHG0136121"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brsuxprbkms01-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_brsuxprbkms02-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_brsuxprbkms03-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_commvault-media-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_commvault-media-servers"
  description  = "role: pr-c-frontend_grp_commvault-media-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_grp_commvault-media-server-ld6.path, nsxt_policy_group.pr-c-frontend_grp_commvault-media-servers-gib.path, nsxt_policy_group.pr-c-frontend_grp_commvault-meida-servers-scc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_commvault-commcell" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_commvault-commcell"
  description  = "role: pr-c-frontend_grp_commvault-commcell"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_grp_commvault-commcell-ld6.path, nsxt_policy_group.pr-c-frontend_grp_commvault-commcell-scc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_commvault-vsa-proxy-servers-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_commvault-vsa-proxy-servers-scc"
  description  = "role: pr-c-frontend_grp_commvault-vsa-proxy-servers-scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprbkvs01.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs02.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs03.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs04.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs05.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_70"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_70"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-46-10.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-11.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-12.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-13.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-14.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-15.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_commvault-commcell-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_commvault-commcell-scc"
  description  = "role: pr-c-frontend_grp_commvault-commcell-scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_72" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_72"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_72"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ld6prapvc01.path, nsxt_policy_group.pr-c-frontend_ip_10-120-134-253.path, nsxt_policy_group.pr-c-frontend_ip_10-180-138-15.path, nsxt_policy_group.pr-c-frontend_grp_commvault-vsa-proxy-servers-ld6.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_74"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_74"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprbkvs01.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs02.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs03.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs04.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs05.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_77" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_77"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_77"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-180-46-35.path, nsxt_policy_group.pr-c-frontend_ip_10-180-46-36.path, nsxt_policy_group.pr-c-frontend_ip_10-180-46-37.path, nsxt_policy_group.pr-c-frontend_ip_10-180-46-38.path, nsxt_policy_group.pr-c-frontend_ip_10-180-46-39.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_78" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_78"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_78"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprbkms01.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkms02.path, nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_87" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_87"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_87"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_bireports.path, nsxt_policy_group.pr-c-frontend_ip_10-1-28-0s23.path, nsxt_policy_group.pr-c-frontend_grp_commvault-backup-networks.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_82"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_82"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-46-10.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-11.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-12.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-13.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-14.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-15.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_84" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_84"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_84"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprbkvs01.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs02.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs03.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs04.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs05.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_90" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_90"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_90"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-46-10.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-11.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-12.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-13.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-14.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-15.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_insightiq-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_insightiq-servers"
  description  = "role: pr-c-frontend_grp_insightiq-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1prcap01-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_isilon-clusters" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_isilon-clusters"
  description  = "role: pr-c-frontend_grp_isilon-clusters"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_isilon-cluster-gib.path, nsxt_policy_group.pr-c-frontend_isilon-cluster-ld6.path, nsxt_policy_group.pr-c-frontend_isilon-cluster-scc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_111" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_111"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_111"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprbkms01.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkms02.path, nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_115" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_115"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_115"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-118-0-0s16.path, nsxt_policy_group.pr-c-frontend_ip_10-209-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_118" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_118"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_118"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-210-46-10.path, nsxt_policy_group.pr-c-frontend_ip_10-210-46-11.path, nsxt_policy_group.pr-c-frontend_ip_10-210-46-12.path, nsxt_policy_group.pr-c-frontend_ip_10-210-46-13.path, nsxt_policy_group.pr-c-frontend_ip_10-210-46-14.path, nsxt_policy_group.pr-c-frontend_ip_10-210-46-15.path, nsxt_policy_group.pr-c-frontend_ip_10-210-46-16.path, nsxt_policy_group.pr-c-frontend_ip_10-210-46-17.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_2"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_2"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_gamingdb-mgmt-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_gibux531-mgmt-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_gibux532-mgmt-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_spbkdb-mgmt-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_45"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_45"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-1-29-38.path, nsxt_policy_group.pr-c-frontend_ip_10-1-29-39.path, nsxt_policy_group.pr-c-frontend_grp_brs-informix-cluster.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_55"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_55"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxd03.path, nsxt_policy_group.pr-c-frontend_sc1uxd04.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_56"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_56"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ld6wnpreap10.path, nsxt_policy_group.pr-c-frontend_sc1wnpreap10.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_openbet-hdr-reporting-dbs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_openbet-hdr-reporting-dbs"
  description  = "role: pr-c-frontend_grp_openbet-hdr-reporting-dbs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxd03.path, nsxt_policy_group.pr-c-frontend_sc1uxd04.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_52" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_52"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_52"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_prod.path, nsxt_policy_group.pr-c-frontend_prodjde.path, nsxt_policy_group.pr-c-frontend_sc1wncpgap11.path, nsxt_policy_group.pr-c-frontend_sc1wnprgap03.path, nsxt_policy_group.pr-c-frontend_sc1wnprgdb02.path, nsxt_policy_group.pr-c-frontend_stj-accu-01.path, nsxt_policy_group.pr-c-frontend_stjux049.path, nsxt_policy_group.pr-c-frontend_sc1wncpgap12.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_64" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_64"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_64"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_prod.path, nsxt_policy_group.pr-c-frontend_prod1.path, nsxt_policy_group.pr-c-frontend_prod1_dr.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_informix-db-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_informix-db-servers"
  description  = "role: pr-c-frontend_grp_informix-db-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprcdb03.path, nsxt_policy_group.pr-c-frontend_sc1uxprcdb04.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-nas-ip-range40-49" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-nas-ip-range40-49"
  description  = "role: CHG0133137"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_10-120-46-40.path, nsxt_policy_group.pr-c-frontend_10-120-46-41.path, nsxt_policy_group.pr-c-frontend_10-120-46-42.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-43.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-44.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-45.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-46.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-47.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-48.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-49.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_16"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_16"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_classa-8.path, nsxt_policy_group.pr-c-frontend_paragon-crisantaverbo.path, nsxt_policy_group.pr-c-frontend_paragon-ellezarmarcelo.path, nsxt_policy_group.pr-c-frontend_paragon-jeanbuenaventura.path, nsxt_policy_group.pr-c-frontend_paragon-mariegracedioniso.path, nsxt_policy_group.pr-c-frontend_paragon-reggiealtarejos.path, nsxt_policy_group.pr-c-frontend_paragon-rommeltomas.path, nsxt_policy_group.pr-c-frontend_paragon-waylansebastian.path, nsxt_policy_group.pr-c-frontend_trg-manilla-16.path, nsxt_policy_group.pr-c-frontend_telaviv-172-18-0-0-22.path, nsxt_policy_group.pr-c-frontend_vpn-gib-24.path, nsxt_policy_group.pr-c-frontend_grp_wp-office-data.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_17"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_17"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_grp_grp-pr-c-xen-sessionhost-xa65.path, nsxt_policy_group.pr-c-frontend_grp_grp-pr-c-xen-desktops.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_29"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_29"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_informix-db-vip.path, nsxt_policy_group.pr-c-frontend_informix-hdr-vip.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_openbet-live-dr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_openbet-live-dr"
  description  = "role: pr-c-frontend_grp_openbet-live-dr"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_openbet-dr-24.path, nsxt_policy_group.pr-c-frontend_openbet-live-24.path, nsxt_policy_group.pr-c-frontend_ip_10-194-140-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_13"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_13"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_scc-backoffice-williamhill-local.path, nsxt_policy_group.pr-c-frontend_int-lb-cdebackoffice-sc1-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_54"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_54"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-99-61.path, nsxt_policy_group.pr-c-frontend_grp_stj-hdr-user-access.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_125" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_125"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_125"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-39-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-210-39-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_18"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_18"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_cdebackoffice-williamhill-local.path, nsxt_policy_group.pr-c-frontend_int-lb-cdebackoffice-sc1-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_7"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_7"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_grp_grp-brocade-svc-control.path, nsxt_policy_group.pr-c-frontend_grp_wily_svrs_scc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-brocade-vtm-admin" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-brocade-vtm-admin"
  description  = "role: pr-c-frontend_grp_grp-brocade-vtm-admin"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brs-checkpoint-vpn-ra.path, nsxt_policy_group.pr-c-frontend_lcw-net-10-1-82-0_23.path, nsxt_policy_group.pr-c-frontend_lcw-net-10-1-86-0_23.path, nsxt_policy_group.pr-c-frontend_stj-net-10-1-74-0_24.path, nsxt_policy_group.pr-c-frontend_krk-eoc-lan.path, nsxt_policy_group.pr-c-frontend_krk-eoc-wifi.path, nsxt_policy_group.pr-c-frontend_10-55-12-74.path, nsxt_policy_group.pr-c-frontend_10-55-14-18.path, nsxt_policy_group.pr-c-frontend_10-55-14-19.path, nsxt_policy_group.pr-c-frontend_10-55-14-20.path, nsxt_policy_group.pr-c-frontend_10-55-14-22.path, nsxt_policy_group.pr-c-frontend_10-55-226-18.path, nsxt_policy_group.pr-c-frontend_10-55-226-19.path, nsxt_policy_group.pr-c-frontend_10-55-226-20.path, nsxt_policy_group.pr-c-frontend_10-55-226-62.path, nsxt_policy_group.pr-c-frontend_10-55-226-74.path, nsxt_policy_group.pr-c-frontend_net_10-55-60-0_28.path, nsxt_policy_group.pr-c-frontend_grp_stj-retail-ias.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_rfc1918" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_rfc1918"
  description  = "role: pr-c-frontend_grp_rfc1918"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_classa-8.path, nsxt_policy_group.pr-c-frontend_classb-12.path, nsxt_policy_group.pr-c-frontend_classc-16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_34"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_34"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-100-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-101-0s27.path, nsxt_policy_group.pr-c-frontend_ip_10-120-102-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_35"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_35"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-44-25.path, nsxt_policy_group.pr-c-frontend_ip_10-120-44-26.path, nsxt_policy_group.pr-c-frontend_ip_10-120-44-27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_32"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_32"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-163-97.path, nsxt_policy_group.pr-c-frontend_ip_10-120-163-98.path, nsxt_policy_group.pr-c-frontend_ip_10-120-132-0s24.path, nsxt_policy_group.pr-c-frontend_grp_scc-management-subnets.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_33"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_33"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_scc-int-lb-cde-stingray01.path, nsxt_policy_group.pr-c-frontend_scc-int-lb-cde-stingray02.path, nsxt_policy_group.pr-c-frontend_grp_puppet-ncx-servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_102" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_102"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_102"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_lcw-robrussell.path, nsxt_policy_group.pr-c-frontend_grp_layer7-access.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_cde-web-any-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_cde-web-any-access"
  description  = "role: pr-c-frontend_grp_cde-web-any-access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_10-121-5-0slash24.path, nsxt_policy_group.pr-c-frontend_net-inv-cde-api-lan.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_euc-team-" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_euc-team-"
  description  = "role: pr-c-frontend_grp_euc-team-"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_wh0004371.path, nsxt_policy_group.pr-c-frontend_test-prod-williamhill.path, nsxt_policy_group.pr-c-frontend_10-1-83-11.path, nsxt_policy_group.pr-c-frontend_10-53-32-107.path, nsxt_policy_group.pr-c-frontend_10-53-32-93.path, nsxt_policy_group.pr-c-frontend_10-53-33-120.path, nsxt_policy_group.pr-c-frontend_10-53-33-56.path, nsxt_policy_group.pr-c-frontend_10-1-82-184.path, nsxt_policy_group.pr-c-frontend_10-1-82-24.path, nsxt_policy_group.pr-c-frontend_10-1-83-154.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_46"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_46"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-180-52-220.path, nsxt_policy_group.pr-c-frontend_ip_10-180-52-221.path, nsxt_policy_group.pr-c-frontend_ip_10-180-52-222.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_53"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_53"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brs-checkpoint-vpn-ra.path, nsxt_policy_group.pr-c-frontend_sc1wnprnap024-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_serveroperations-27.path, nsxt_policy_group.pr-c-frontend_ip_10-1-82-109.path, nsxt_policy_group.pr-c-frontend_ip_10-1-82-178.path, nsxt_policy_group.pr-c-frontend_ip_10-1-82-183.path, nsxt_policy_group.pr-c-frontend_ip_10-1-82-189.path, nsxt_policy_group.pr-c-frontend_ip_10-1-82-235.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_infoblox-all-dns-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_infoblox-all-dns-servers"
  description  = "role: pr-c-frontend_grp_infoblox-all-dns-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brsns01.path, nsxt_policy_group.pr-c-frontend_brsns02.path, nsxt_policy_group.pr-c-frontend_gibns01.path, nsxt_policy_group.pr-c-frontend_gibns02.path, nsxt_policy_group.pr-c-frontend_sccns01.path, nsxt_policy_group.pr-c-frontend_sccns02.path, nsxt_policy_group.pr-c-frontend_ld6ns01.path, nsxt_policy_group.pr-c-frontend_ld6ns02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_73" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_73"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_73"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ld6prapvc01.path, nsxt_policy_group.pr-c-frontend_grp_commvault-vsa-proxy-servers-ld6.path, nsxt_policy_group.pr-c-frontend_grp_commvault-vsa-proxy-servers-gib.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_101"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_101"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sccuxstnmg03.path, nsxt_policy_group.pr-c-frontend_ip_10-120-141-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_commvault-backup-networks" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_commvault-backup-networks"
  description  = "role: pr-c-frontend_grp_commvault-backup-networks"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brs-dev-test.path, nsxt_policy_group.pr-c-frontend_brs-dev-test-old.path, nsxt_policy_group.pr-c-frontend_gib-corp-tier.path, nsxt_policy_group.pr-c-frontend_gib-ncde-db-tier.path, nsxt_policy_group.pr-c-frontend_gib-ncde-mgmt-tier.path, nsxt_policy_group.pr-c-frontend_sc1-cde-frontend-hdr-tier.path, nsxt_policy_group.pr-c-frontend_sc1-ncde-app-tier.path, nsxt_policy_group.pr-c-frontend_sc1-ncde-frontend-ods-tier.path, nsxt_policy_group.pr-c-frontend_sc1-ncde-mgmt-tier.path, nsxt_policy_group.pr-c-frontend_sc1-retail-mgmt-tier.path, nsxt_policy_group.pr-c-frontend_sc1-ad-tier.path, nsxt_policy_group.pr-c-frontend_sc1-monitoring.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_79" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_79"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_79"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_grp_commvault-commcell-scc.path, nsxt_policy_group.pr-c-frontend_grp_commvault-meida-servers-scc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_97"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_97"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxpremn74.path, nsxt_policy_group.pr-c-frontend_ip_10-180-142-164.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_81"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_81"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-46-10.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-11.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-12.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-13.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-14.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-15.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_89" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_89"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_89"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-46-10.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-11.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-12.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-13.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-14.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-15.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_91" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_91"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_91"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_10-120-46-31.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-30.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-32.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_whc-nexus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_whc-nexus"
  description  = "role: CHG0117312"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_prdxnex01box001-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_prdxnex01box002-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_prdxnex01box003-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_112" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_112"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_112"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprbkms01.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkms02.path, nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_113" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_113"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_113"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ld6uxpremn11.path, nsxt_policy_group.pr-c-frontend_sc1uxpremn006.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_122" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_122"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_122"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-180-39-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-210-39-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_120" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_120"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_120"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-39-103.path, nsxt_policy_group.pr-c-frontend_ip_10-120-39-104.path, nsxt_policy_group.pr-c-frontend_ip_10-120-39-105.path, nsxt_policy_group.pr-c-frontend_ip_10-120-39-106.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_133" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_133"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_133"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-39-103.path, nsxt_policy_group.pr-c-frontend_ip_10-120-39-104.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_142" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_142"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_142"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_aws-f5-slash24.path, nsxt_policy_group.pr-c-frontend_aws-irl-f5-slash24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_137" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_137"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_137"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_10-120-46-16.path, nsxt_policy_group.pr-c-frontend_10-120-46-17.path, nsxt_policy_group.pr-c-frontend_10-120-46-18.path, nsxt_policy_group.pr-c-frontend_10-120-46-19.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-10.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-11.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-12.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-13.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-14.path, nsxt_policy_group.pr-c-frontend_ip_10-120-46-15.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_sc1-apic-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_sc1-apic-servers"
  description  = "role: pr-c-frontend_grp_sc1-apic-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_uk-sc1-apic1.path, nsxt_policy_group.pr-c-frontend_uk-sc1-apic2.path, nsxt_policy_group.pr-c-frontend_uk-sc1-apic3.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_88" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_88"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_88"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_scc-int-lb-cde-stingray01.path, nsxt_policy_group.pr-c-frontend_scc-int-lb-cde-stingray02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_cde-backoffice-web-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_cde-backoffice-web-servers"
  description  = "role: pr-c-frontend_grp_cde-backoffice-web-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_10-120-38-11.path, nsxt_policy_group.pr-c-frontend_10-120-38-12.path, nsxt_policy_group.pr-c-frontend_10-120-38-13.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_cde_crypto_app_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_cde_crypto_app_servers"
  description  = "role: pr-c-frontend_grp_cde_crypto_app_servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprcap31.path, nsxt_policy_group.pr-c-frontend_sc1uxprcap32.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_141" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_141"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_141"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_cdeproxy-williamhill-remote.path, nsxt_policy_group.pr-c-frontend_int-lb-cdeproxy.path, nsxt_policy_group.pr-c-frontend_ip_10-180-44-28.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_vmc-sddcs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_vmc-sddcs"
  description  = "role: pr-c-frontend_grp_vmc-sddcs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_vmc-retail-test.path, nsxt_policy_group.pr-c-frontend_ip_10-156-5-0s24.path, nsxt_policy_group.pr-c-frontend_grp_vmc-sddc-retail-production.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_whgroup_ad_servers-chg0144834" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_whgroup_ad_servers-chg0144834"
  description  = "role: pr-c-frontend_grp_whgroup_ad_servers-chg0144834"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_bfawnpredc01.path, nsxt_policy_group.pr-c-frontend_brswnpredc01.path, nsxt_policy_group.pr-c-frontend_brswnpredc02_ip_10-210-194-12.path, nsxt_policy_group.pr-c-frontend_brswnpredc03-chg0144834.path, nsxt_policy_group.pr-c-frontend_gibwnpredc02_ip_10-180-194-12.path, nsxt_policy_group.pr-c-frontend_gibwnpredc03_ip_10-180-194-13.path, nsxt_policy_group.pr-c-frontend_irewnprdc01.path, nsxt_policy_group.pr-c-frontend_irewnprdc02.path, nsxt_policy_group.pr-c-frontend_nvawnprdc01.path, nsxt_policy_group.pr-c-frontend_nvawnprdc02.path, nsxt_policy_group.pr-c-frontend_krawnpredc01.path, nsxt_policy_group.pr-c-frontend_krawnpredc02.path, nsxt_policy_group.pr-c-frontend_ld6wnpredc01-new.path, nsxt_policy_group.pr-c-frontend_ld6wnpredc02-new.path, nsxt_policy_group.pr-c-frontend_mnlwnpredc02_ip_10-123-197-11.path, nsxt_policy_group.pr-c-frontend_mnlwnpredc03.path, nsxt_policy_group.pr-c-frontend_sc1wnpredc01.path, nsxt_policy_group.pr-c-frontend_sc1wnpredc02.path, nsxt_policy_group.pr-c-frontend_sc1wnpredc03_ip_10-120-194-13.path, nsxt_policy_group.pr-c-frontend_sc1wnpredc04_ip_10-120-194-14.path, nsxt_policy_group.pr-c-frontend_sc1wnpredc05_ip_10-120-194-15.path, nsxt_policy_group.pr-c-frontend_sc1wnpredc08_ip_10-120-194-18.path, nsxt_policy_group.pr-c-frontend_sofwnpredc01.path, nsxt_policy_group.pr-c-frontend_sofwnpredc02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_euc_mgmt_server-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_euc_mgmt_server-group-chg0142765"
  description  = "role: pr-c-frontend_grp_euc_mgmt_server-group-chg0142765"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brsapprcmg002-group-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_on_premise_datacentre_vlans-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_on_premise_datacentre_vlans-group-chg0142765"
  description  = "role: pr-c-frontend_grp_on_premise_datacentre_vlans-group-chg0142765"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-0-0s16.path, nsxt_policy_group.pr-c-frontend_ip_10-210-0-0s16.path, nsxt_policy_group.pr-c-frontend_ip_10-180-0-0s16.path, nsxt_policy_group.pr-c-frontend_ip_10-112-0-0s16.path, nsxt_policy_group.pr-c-frontend_ip_10-19-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_wh_nets-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_wh_nets-chg0143200"
  description  = "role: pr-c-frontend_grp_wh_nets-chg0143200"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-0-0-0s8.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_splunk_heavy_forwarders-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_splunk_heavy_forwarders-chg0143200"
  description  = "role: pr-c-frontend_grp_splunk_heavy_forwarders-chg0143200"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxpremn002.path, nsxt_policy_group.pr-c-frontend_sc1uxpremn003.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_splunk_deployment_server-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_splunk_deployment_server-chg0143200"
  description  = "role: pr-c-frontend_grp_splunk_deployment_server-chg0143200"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_splunkdeployment-sc1-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_wh_nets-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_wh_nets-chg0142763"
  description  = "role: pr-c-frontend_grp_wh_nets-chg0142763"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_splunk_heavy_forwarders-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_splunk_heavy_forwarders-chg0142763"
  description  = "role: pr-c-frontend_grp_splunk_heavy_forwarders-chg0142763"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxpremn002.path, nsxt_policy_group.pr-c-frontend_sc1uxpremn003.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_splunk_deployment_server-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_splunk_deployment_server-chg0142763"
  description  = "role: pr-c-frontend_grp_splunk_deployment_server-chg0142763"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_splunkdeployment-sc1-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_ras-vpn-pool"
  description  = "role: pr-c-frontend_grp_ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_grp_ld6-ras-vpn-pool.path, nsxt_policy_group.pr-c-frontend_grp_sc1-ras-vpn-pool.path, nsxt_policy_group.pr-c-frontend_grp_mrg-ras-vpn-pool.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_43"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_43"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-44-25.path, nsxt_policy_group.pr-c-frontend_ip_10-120-44-26.path, nsxt_policy_group.pr-c-frontend_ip_10-120-44-27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_rundeck-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_rundeck-servers"
  description  = "role: pr-c-frontend_grp_rundeck-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxpreap237_ip_10-120-163-237.path, nsxt_policy_group.pr-c-frontend_sc1uxpreap238_ip_10-120-163-238.path, nsxt_policy_group.pr-c-frontend_sc1uxpreap239_ip_10-120-163-239.path, nsxt_policy_group.pr-c-frontend_sc1uxpreap242.path, nsxt_policy_group.pr-c-frontend_sc1uxrdk.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_wily-svrs_all" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_wily-svrs_all"
  description  = "role: pr-c-frontend_grp_wily-svrs_all"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_grp_wily_svrs_brs.path, nsxt_policy_group.pr-c-frontend_grp_wily_svrs_scc.path, nsxt_policy_group.pr-c-frontend_grp_wily_svrs_gib.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_wily-access-group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_wily-access-group"
  description  = "role: pr-c-frontend_grp_wily-access-group"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_classa-8.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_42"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_42"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_net_10-120-37-0m24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-50-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-52-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-38-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-39-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-67-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-72-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_39"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_39"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-44-25.path, nsxt_policy_group.pr-c-frontend_ip_10-120-44-26.path, nsxt_policy_group.pr-c-frontend_ip_10-120-44-27.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_93"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_93"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brsux910.path, nsxt_policy_group.pr-c-frontend_gibux910.path, nsxt_policy_group.pr-c-frontend_ld6uxpreds01.path, nsxt_policy_group.pr-c-frontend_sc1uxpreds01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_katello" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_katello"
  description  = "role: pr-c-frontend_grp_katello"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxstnmg01.path, nsxt_policy_group.pr-c-frontend_brsuxkat.path, nsxt_policy_group.pr-c-frontend_gibuxkat.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_wsus" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_wsus"
  description  = "role: pr-c-frontend_grp_wsus"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brswsus.path, nsxt_policy_group.pr-c-frontend_gibwsus.path, nsxt_policy_group.pr-c-frontend_sc1wnprein01.path, nsxt_policy_group.pr-c-frontend_stjwsus.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_splunk-logger" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_splunk-logger"
  description  = "role: pr-c-frontend_grp_splunk-logger"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_gibux-hf1.path, nsxt_policy_group.pr-c-frontend_gibux-indx1.path, nsxt_policy_group.pr-c-frontend_gibux-indx2.path, nsxt_policy_group.pr-c-frontend_gibuxpremn01.path, nsxt_policy_group.pr-c-frontend_gibuxpremn03.path, nsxt_policy_group.pr-c-frontend_gibuxpremn04.path, nsxt_policy_group.pr-c-frontend_sc1uxpromn012.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-38.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-39.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-45.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-46.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_webproxies-cx-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_webproxies-cx-scc"
  description  = "role: pr-c-frontend_grp_webproxies-cx-scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_10-121-5-0slash24.path, nsxt_policy_group.pr-c-frontend_10-121-7-0slash24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_67" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_67"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_67"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_grp_ad-child-dc-group.path, nsxt_policy_group.pr-c-frontend_grp_whgroup-ad-servers.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_uim-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_uim-servers"
  description  = "role: CHG0079749,CHG0119559"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brsuxpremn65.path, nsxt_policy_group.pr-c-frontend_brsuxpremn66.path, nsxt_policy_group.pr-c-frontend_sc1uxpremn65.path, nsxt_policy_group.pr-c-frontend_sc1uxpremn66.path, nsxt_policy_group.pr-c-frontend_ld6uxpremn13.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_rds-kms-server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_rds-kms-server"
  description  = "role: KMS/RDS license servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brswndremg002.path, nsxt_policy_group.pr-c-frontend_sc1wnpremg002.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_61" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_61"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_61"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-65-68.path, nsxt_policy_group.pr-c-frontend_ip_10-210-65-68.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-commvault-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-commvault-svrs"
  description  = "role: CHG0112231"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprbkms01.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkms02.path, nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-migrated_network_103" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-migrated_network_103"
  description  = "role: pr-c-frontend_grp_scc-migrated_network_103"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-0-0s16.path, nsxt_policy_group.pr-c-frontend_ip_10-121-0-0s16.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_skybox-appliances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_skybox-appliances"
  description  = "role: CHG0122435"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1appresc02-data.path, nsxt_policy_group.pr-c-frontend_sc1appresc03-data.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-whapi-c1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-whapi-c1"
  description  = "role: CHG0144060"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1apprcwb01-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb02-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb03-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb04-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb09-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb10-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb11-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb12-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-whapi-c2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-whapi-c2"
  description  = "role: CHG0144060"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1apprcwb005-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb006-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb007-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb008-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb013-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb014-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb016-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb015-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-whapi-c3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-whapi-c3"
  description  = "role: CHG0144060"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1apprcwb017-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb018-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb019-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb020-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb021-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb022-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb023-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb024-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-scc-pr-cwb-layer7-top" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-scc-pr-cwb-layer7-top"
  description  = "role: pr-c-frontend_grp_grp-scc-pr-cwb-layer7-top"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1apprcwb01.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb02.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb03.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb04.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-scc-pr-cwb-layer7new-top" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-scc-pr-cwb-layer7new-top"
  description  = "role: pr-c-frontend_grp_grp-scc-pr-cwb-layer7new-top"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1apprcwb005.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb006.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb007.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb008.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-scc-pr-cwb-layer7-top-3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-scc-pr-cwb-layer7-top-3"
  description  = "role: pr-c-frontend_grp_grp-scc-pr-cwb-layer7-top-3"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1apprcwb009-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb010-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb011-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb012-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb013-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb014-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb015-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_sc1apprcwb016-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_puppet-ncx-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_puppet-ncx-servers"
  description  = "role: pr-c-frontend_grp_puppet-ncx-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_puppet-ncx-scc-ca-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_puppet-ncx-scc-db-prod-williamhill-plc.path, nsxt_policy_group.pr-c-frontend_puppet-ncx-scc-prod-williamhill-plc.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_scc-management-subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_scc-management-subnets"
  description  = "role: pr-c-frontend_grp_scc-management-subnets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-120-129-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-131-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-132-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-133-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-134-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-136-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-137-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-141-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-143-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-145-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-146-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-147-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-148-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-149-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-152-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-153-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-159-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-162-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-163-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-180-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-193-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-194-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-195-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-39-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-120-64-0s24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_commvault-media-server-ld6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_commvault-media-server-ld6"
  description  = "role: pr-c-frontend_grp_commvault-media-server-ld6"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ld6uxprbkms01.path, nsxt_policy_group.pr-c-frontend_ld6uxprbkms02.path, nsxt_policy_group.pr-c-frontend_ld6uxprbkms03.path, nsxt_policy_group.pr-c-frontend_ld6uxprbkms04.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_commvault-media-servers-gib" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_commvault-media-servers-gib"
  description  = "role: pr-c-frontend_grp_commvault-media-servers-gib"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_gibuxprbkms01.path, nsxt_policy_group.pr-c-frontend_gibuxprbkms02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_commvault-meida-servers-scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_commvault-meida-servers-scc"
  description  = "role: pr-c-frontend_grp_commvault-meida-servers-scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxprbkms01.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkms02.path, nsxt_policy_group.pr-c-frontend_sc1uxprbkvs01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_commvault-commcell-ld6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_commvault-commcell-ld6"
  description  = "role: pr-c-frontend_grp_commvault-commcell-ld6"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ld6wnprbkcs01.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_commvault-vsa-proxy-servers-ld6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_commvault-vsa-proxy-servers-ld6"
  description  = "role: pr-c-frontend_grp_commvault-vsa-proxy-servers-ld6"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ld6uxprbkvs01.path, nsxt_policy_group.pr-c-frontend_ld6uxprbkvs02.path, nsxt_policy_group.pr-c-frontend_ld6uxprbkvs03.path, nsxt_policy_group.pr-c-frontend_ld6uxprbkvs04.path, nsxt_policy_group.pr-c-frontend_ld6uxprbkvs05.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_brs-informix-cluster" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_brs-informix-cluster"
  description  = "role: CHG0137980"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brsux279_280-p1-vip.path, nsxt_policy_group.pr-c-frontend_brsux279_280-p2-vip.path, nsxt_policy_group.pr-c-frontend_brsux279_280-p3-vip.path, nsxt_policy_group.pr-c-frontend_brsux279_280-stg-vip.path, nsxt_policy_group.pr-c-frontend_brsux279_280-sys-vip.path, nsxt_policy_group.pr-c-frontend_brsux279_280-tem-vip.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_wp-office-data" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_wp-office-data"
  description  = "role: CHG0019704"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_wp-4th-data.path, nsxt_policy_group.pr-c-frontend_wp-5th-data-24.path, nsxt_policy_group.pr-c-frontend_wp-6th-data-23.path, nsxt_policy_group.pr-c-frontend_wp-gnd-data-24.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-pr-c-xen-sessionhost-xa65" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-pr-c-xen-sessionhost-xa65"
  description  = "role: CHG0018190"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa03.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa04.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa05.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa06.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa07.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa08.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa09.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa10.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa11.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa12.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa13.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa14.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa01.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa02.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa21.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa22.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa23.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa24.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa25.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa26.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa27.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa28.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-xa29.path, nsxt_policy_group.pr-c-frontend_sc1wnprexa35.path, nsxt_policy_group.pr-c-frontend_sc1wnprexa36.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-pr-c-xen-desktops" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-pr-c-xen-desktops"
  description  = "role: CHG0018815"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1wnprexp01.path, nsxt_policy_group.pr-c-frontend_sc1wnprexp100.path, nsxt_policy_group.pr-c-frontend_sc1wnprexp95.path, nsxt_policy_group.pr-c-frontend_sc1wnprexp96.path, nsxt_policy_group.pr-c-frontend_sc1wnprexp97.path, nsxt_policy_group.pr-c-frontend_sc1wnprexp98.path, nsxt_policy_group.pr-c-frontend_sc1wnprexp99.path, nsxt_policy_group.pr-c-frontend_10-120-39-128-28.path, nsxt_policy_group.pr-c-frontend_10-120-39-144.path, nsxt_policy_group.pr-c-frontend_10-120-39-52-30.path, nsxt_policy_group.pr-c-frontend_10-120-39-56-29.path, nsxt_policy_group.pr-c-frontend_10-120-39-64-26.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_stj-hdr-user-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_stj-hdr-user-access"
  description  = "role: pr-c-frontend_grp_stj-hdr-user-access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_stj-alan-huner-backup.path, nsxt_policy_group.pr-c-frontend_stj-alan-hunter.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_wily_svrs_scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_wily_svrs_scc"
  description  = "role: pr-c-frontend_grp_wily_svrs_scc"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1uxpremn105.path, nsxt_policy_group.pr-c-frontend_sc1uxpremn106.path, nsxt_policy_group.pr-c-frontend_sc1uxpremn107.path, nsxt_policy_group.pr-c-frontend_sc1uxpremn108.path, nsxt_policy_group.pr-c-frontend_sc1uxpremn120.path, nsxt_policy_group.pr-c-frontend_sc1uxpremn121.path, nsxt_policy_group.pr-c-frontend_ip_10-120-163-31.path, nsxt_policy_group.pr-c-frontend_ip_10-120-163-32.path, nsxt_policy_group.pr-c-frontend_ip_10-120-163-33.path, nsxt_policy_group.pr-c-frontend_ip_10-120-163-34.path, nsxt_policy_group.pr-c-frontend_ip_10-120-163-36.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_stj-retail-ias" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_stj-retail-ias"
  description  = "role: pr-c-frontend_grp_stj-retail-ias"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_10-1-58-100.path, nsxt_policy_group.pr-c-frontend_10-1-58-101.path, nsxt_policy_group.pr-c-frontend_10-1-58-102.path, nsxt_policy_group.pr-c-frontend_10-1-58-103.path, nsxt_policy_group.pr-c-frontend_10-1-58-104.path, nsxt_policy_group.pr-c-frontend_10-1-58-97.path, nsxt_policy_group.pr-c-frontend_10-1-58-98.path, nsxt_policy_group.pr-c-frontend_10-1-58-99.path, nsxt_policy_group.pr-c-frontend_10-1-58-106.path, nsxt_policy_group.pr-c-frontend_10-1-58-107.path, nsxt_policy_group.pr-c-frontend_10-1-58-29.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_layer7-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_layer7-access"
  description  = "role: pr-c-frontend_grp_layer7-access"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brswn109.path, nsxt_policy_group.pr-c-frontend_grp_grp-whapi-snat.path, nsxt_policy_group.pr-c-frontend_grp_grp-f5-top.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_commvault-vsa-proxy-servers-gib" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_commvault-vsa-proxy-servers-gib"
  description  = "role: pr-c-frontend_grp_commvault-vsa-proxy-servers-gib"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-180-46-35.path, nsxt_policy_group.pr-c-frontend_ip_10-180-46-36.path, nsxt_policy_group.pr-c-frontend_ip_10-180-46-37.path, nsxt_policy_group.pr-c-frontend_ip_10-180-46-38.path, nsxt_policy_group.pr-c-frontend_ip_10-180-46-39.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_vmc-sddc-retail-production" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_vmc-sddc-retail-production"
  description  = "role: pr-c-frontend_grp_vmc-sddc-retail-production"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_vmc-retail-production-vsphere-mgmt.path, nsxt_policy_group.pr-c-frontend_vmc-retail-production-10-233-0-0s24.path, nsxt_policy_group.pr-c-frontend_vmc-retail-production-services-mgmt.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_ld6-ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_ld6-ras-vpn-pool"
  description  = "role: pr-c-frontend_grp_ld6-ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_192-168-48-0s20.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_sc1-ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_sc1-ras-vpn-pool"
  description  = "role: pr-c-frontend_grp_sc1-ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_192-168-12-0s22.path, nsxt_policy_group.pr-c-frontend_ip_192-168-16-0s22.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_mrg-ras-vpn-pool" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_mrg-ras-vpn-pool"
  description  = "role: pr-c-frontend_grp_mrg-ras-vpn-pool"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-30-200-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-30-202-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-40-200-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-40-202-0s24.path, nsxt_policy_group.pr-c-frontend_ip_10-130-200-0s23.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_wily_svrs_brs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_wily_svrs_brs"
  description  = "role: pr-c-frontend_grp_wily_svrs_brs"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-210-163-95.path, nsxt_policy_group.pr-c-frontend_ip_10-210-163-96.path, nsxt_policy_group.pr-c-frontend_ip_10-210-163-97.path, nsxt_policy_group.pr-c-frontend_ip_10-210-163-98.path, nsxt_policy_group.pr-c-frontend_ip_10-210-163-99.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_wily_svrs_gib" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_wily_svrs_gib"
  description  = "role: pr-c-frontend_grp_wily_svrs_gib"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_ip_10-180-163-211.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-212.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-213.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-214.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-218.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-102.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-220.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-221.path, nsxt_policy_group.pr-c-frontend_ip_10-180-163-40.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_ad-child-dc-group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_ad-child-dc-group"
  description  = "role: CHG0017397"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_sc1-wn-pre-dc03.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-dc04.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-dc05.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-dc06.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-dc07.path, nsxt_policy_group.pr-c-frontend_sc1-wn-pre-dc08.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_whgroup-ad-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_whgroup-ad-servers"
  description  = "role: pr-c-frontend_grp_whgroup-ad-servers"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_brswnpredc02_ip_10-210-194-12.path, nsxt_policy_group.pr-c-frontend_brswnpredc03.path, nsxt_policy_group.pr-c-frontend_gibwnpredc02_ip_10-180-194-12.path, nsxt_policy_group.pr-c-frontend_gibwnpredc03_ip_10-180-194-13.path, nsxt_policy_group.pr-c-frontend_mnlwnpredc02_ip_10-123-197-11.path, nsxt_policy_group.pr-c-frontend_sc1wnpredc03_ip_10-120-194-13.path, nsxt_policy_group.pr-c-frontend_sc1wnpredc04_ip_10-120-194-14.path, nsxt_policy_group.pr-c-frontend_sc1wnpredc05_ip_10-120-194-15.path, nsxt_policy_group.pr-c-frontend_sc1wnpredc08_ip_10-120-194-18.path, nsxt_policy_group.pr-c-frontend_ld6wnpredc01-new.path, nsxt_policy_group.pr-c-frontend_ld6wnpredc02-new.path, nsxt_policy_group.pr-c-frontend_bfawnpredc01.path, nsxt_policy_group.pr-c-frontend_krawnpredc01.path, nsxt_policy_group.pr-c-frontend_krawnpredc02.path, nsxt_policy_group.pr-c-frontend_mnlwnpredc03.path, nsxt_policy_group.pr-c-frontend_sofwnpredc01.path, nsxt_policy_group.pr-c-frontend_sofwnpredc02.path, nsxt_policy_group.pr-c-frontend_brswnpredc01.path, nsxt_policy_group.pr-c-frontend_sc1wnpredc01.path, nsxt_policy_group.pr-c-frontend_sc1wnpredc02.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-whapi-snat" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-whapi-snat"
  description  = "role: pr-c-frontend_grp_grp-whapi-snat"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_svr-cpr-whapi-snat240-vi.path, nsxt_policy_group.pr-c-frontend_svr-cpr-whapi-snat242-vi.path, nsxt_policy_group.pr-c-frontend_svr-cpr-whapi-snat241-vi.path]
    }
  }
}
resource "nsxt_policy_group" "pr-c-frontend_grp_grp-f5-top" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp_grp-f5-top"
  description  = "role: pr-c-frontend_grp_grp-f5-top"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.pr-c-frontend_svr-f5top01-re.path, nsxt_policy_group.pr-c-frontend_svr-f5top02-re.path, nsxt_policy_group.pr-c-frontend_svr-f5top03-re.path]
    }
  }
}
