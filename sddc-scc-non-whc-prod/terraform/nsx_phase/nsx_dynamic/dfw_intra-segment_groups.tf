/*========================================

###########################################################################
###########################################################################
###                                                                     ###
###             INTRA-SEGMENT GROUPS - NOT MIGRATED FROM SCC            ###
###                                                                     ###
###########################################################################
###########################################################################

========================================*/

resource "nsxt_policy_group" "intra-segment_10-120-100-0s24v262" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-100-0s24v262"
  description  = "role: intra-segment, ip: [10.120.100.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-101-0s27v263" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-101-0s27v263"
  description  = "role: intra-segment, ip: [10.120.101.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.101.0/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-102-0s24v264" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-102-0s24v264"
  description  = "role: intra-segment, ip: [10.120.102.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.102.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-103-0s29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-103-0s29"
  description  = "role: intra-segment, ip: [10.120.103.0/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.103.0/29"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-129-0s24v301" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-129-0s24v301"
  description  = "role: intra-segment, ip: [10.120.129.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.129.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-131-0s24v303" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-131-0s24v303"
  description  = "role: intra-segment, ip: [10.120.131.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.131.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-132-0s24v304" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-132-0s24v304"
  description  = "role: intra-segment, ip: [10.120.132.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.132.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-136-0s24v309" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-136-0s24v309"
  description  = "role: intra-segment, ip: [10.120.136.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-137-0s24v310" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-137-0s24v310"
  description  = "role: intra-segment, ip: [10.120.137.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.137.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-139-0s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-139-0s27"
  description  = "role: intra-segment, ip: [10.120.139.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.139.0/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-140-0s24v320" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-140-0s24v320"
  description  = "role: intra-segment, ip: [10.120.140.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-141-0s24v321" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-141-0s24v321"
  description  = "role: intra-segment, ip: [10.120.141.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-143-64s27v334" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-143-64s27v334"
  description  = "role: intra-segment, ip: [10.120.143.64/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.64/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-145-0s24v341" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-145-0s24v341"
  description  = "role: intra-segment, ip: [10.120.145.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-146-0s24v342" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-146-0s24v342"
  description  = "role: intra-segment, ip: [10.120.146.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-148-0s24v344" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-148-0s24v344"
  description  = "role: intra-segment, ip: [10.120.148.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.148.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-149-0s24v345" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-149-0s24v345"
  description  = "role: intra-segment, ip: [10.120.149.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.149.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-151-0s24v347" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-151-0s24v347"
  description  = "role: intra-segment, ip: [10.120.151.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-152-0s24v348" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-152-0s24v348"
  description  = "role: intra-segment, ip: [10.120.152.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.152.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-153-0s24v349" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-153-0s24v349"
  description  = "role: intra-segment, ip: [10.120.153.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-159-96s27v365" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-159-96s27v365"
  description  = "role: intra-segment, ip: [10.120.159.96/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.159.96/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-161-224s27v385" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-161-224s27v385"
  description  = "role: intra-segment, ip: [10.120.161.224/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.161.224/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-162-0s24v398" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-162-0s24v398"
  description  = "role: intra-segment, ip: [10.120.162.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.162.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-163-0s24v399" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-163-0s24v399"
  description  = "role: intra-segment, ip: [10.120.163.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-170-0s25v450" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-170-0s25v450"
  description  = "role: intra-segment, ip: [10.120.170.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.170.0/25"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-170-128s25v451" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-170-128s25v451"
  description  = "role: intra-segment, ip: [10.120.170.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.170.128/25"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-172-0s24v453" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-172-0s24v453"
  description  = "role: intra-segment, ip: [10.120.172.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.172.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-173-0s25v460" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-173-0s25v460"
  description  = "role: intra-segment, ip: [10.120.173.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.173.0/25"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-173-128s25v461" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-173-128s25v461"
  description  = "role: intra-segment, ip: [10.120.173.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.173.128/25"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-177-0s25v480" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-177-0s25v480"
  description  = "role: intra-segment, ip: [10.120.177.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.177.0/25"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-180-0s25v485" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-180-0s25v485"
  description  = "role: intra-segment, ip: [10.120.180.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.0/25"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-180-128s25v486" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-180-128s25v486"
  description  = "role: intra-segment, ip: [10.120.180.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.180.128/25"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-192-128s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-192-128s27"
  description  = "role: intra-segment, ip: [10.120.192.128/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.128/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-192-160s29v565" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-192-160s29v565"
  description  = "role: intra-segment, ip: [10.120.192.160/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.160/29"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-192-168s29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-192-168s29"
  description  = "role: intra-segment, ip: [10.120.192.168/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.168/29"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-193-224s27v575" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-193-224s27v575"
  description  = "role: intra-segment, ip: [10.120.193.224/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.224/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-194-0s26v576" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-194-0s26v576"
  description  = "role: intra-segment, ip: [10.120.194.0/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.0/26"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-194-192s26v579" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-194-192s26v579"
  description  = "role: intra-segment, ip: [10.120.194.192/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.192/26"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-194-64s26v577" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-194-64s26v577"
  description  = "role: intra-segment, ip: [10.120.194.64/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.64/26"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-195-0s24v580" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-195-0s24v580"
  description  = "role: intra-segment, ip: [10.120.195.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.195.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-196-0s24v581" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-196-0s24v581"
  description  = "role: intra-segment, ip: [10.120.196.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.196.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-208-0s24v650" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-208-0s24v650"
  description  = "role: intra-segment, ip: [10.120.208.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.208.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-216-0s21v397" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-216-0s21v397"
  description  = "role: intra-segment, ip: [10.120.216.0/21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.216.0/21"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-254-208s29v989" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-254-208s29v989"
  description  = "role: intra-segment, ip: [10.120.254.208/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.254.208/29"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-32-128s27v104" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-32-128s27v104"
  description  = "role: intra-segment, ip: [10.120.32.128/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.32.128/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-32-96s27v103" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-32-96s27v103"
  description  = "role: intra-segment, ip: [10.120.32.96/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.32.96/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-33-0s29v109" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-33-0s29v109"
  description  = "role: intra-segment, ip: [10.120.33.0/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.0/29"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-33-160s27v115" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-33-160s27v115"
  description  = "role: intra-segment, ip: [10.120.33.160/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.160/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-36-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-36-0s24"
  description  = "role: intra-segment, ip: [10.120.36.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.36.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-37-0s24v121" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-37-0s24v121"
  description  = "role: intra-segment, ip: [10.120.37.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.37.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-38-0s24v122" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-38-0s24v122"
  description  = "role: intra-segment, ip: [10.120.38.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.38.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-39-0s24v123" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-39-0s24v123"
  description  = "role: intra-segment, ip: [10.120.39.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-43-0s24v124" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-43-0s24v124"
  description  = "role: intra-segment, ip: [10.120.43.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.43.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-44-0s23v134" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-44-0s23v134"
  description  = "role: intra-segment, ip: [10.120.44.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.44.0/23"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-46-0s25v140" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-46-0s25v140"
  description  = "role: intra-segment, ip: [10.120.46.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.0/25"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-50-0s24v160" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-50-0s24v160"
  description  = "role: intra-segment, ip: [10.120.50.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.50.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-64-128s27v204" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-64-128s27v204"
  description  = "role: intra-segment, ip: [10.120.64.128/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.64.128/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-64-160s27v205" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-64-160s27v205"
  description  = "role: intra-segment, ip: [10.120.64.160/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.64.160/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-65-128s27v235" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-65-128s27v235"
  description  = "role: intra-segment, ip: [10.120.65.128/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.65.128/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-65-64s27v232" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-65-64s27v232"
  description  = "role: intra-segment, ip: [10.120.65.64/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.65.64/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-65-96s27v234" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-65-96s27v234"
  description  = "role: intra-segment, ip: [10.120.65.96/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.65.96/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-66-0s24v210" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-66-0s24v210"
  description  = "role: intra-segment, ip: [10.120.66.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.66.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-67-0s24v211" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-67-0s24v211"
  description  = "role: intra-segment, ip: [10.120.67.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.67.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-69-192s27v219" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-69-192s27v219"
  description  = "role: intra-segment, ip: [10.120.69.192/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.192/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-69-224s27v218" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-69-224s27v218"
  description  = "role: intra-segment, ip: [10.120.69.224/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.224/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-69-96s27v216" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-69-96s27v216"
  description  = "role: intra-segment, ip: [10.120.69.96/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.96/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-70-0s27v223" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-70-0s27v223"
  description  = "role: intra-segment, ip: [10.120.70.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.70.0/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-71-0s24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-71-0s24"
  description  = "role: intra-segment, ip: [10.120.71.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.71.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-72-0s24v222" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-72-0s24v222"
  description  = "role: intra-segment, ip: [10.120.72.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.72.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-74-0s23v231" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-74-0s23v231"
  description  = "role: intra-segment, ip: [10.120.74.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.74.0/23"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-76-0s24v233" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-76-0s24v233"
  description  = "role: intra-segment, ip: [10.120.76.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.76.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-98-0s24v260" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-98-0s24v260"
  description  = "role: intra-segment, ip: [10.120.98.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.98.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-99-0s24v261" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-99-0s24v261"
  description  = "role: intra-segment, ip: [10.120.99.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.0/24"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-156-4-0s25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-156-4-0s25"
  description  = "role: intra-segment, ip: [10.156.4.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.4.0/25"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-156-5-128s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-156-5-128s27"
  description  = "role: intra-segment, ip: [10.156.5.128/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.5.128/27"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-33-192s26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-33-192s26"
  description  = "role: intra-segment, ip: [10.120.33.192/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.192/26"]
    }
  }
}
resource "nsxt_policy_group" "intra-segment_10-120-194-128s27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_10-120-194-128s27"
  description  = "role: intra-segment, ip: [10.120.194.128/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.128/27"]
    }
  }
}

/*======================================
#### object-groups ####
========================================*/

