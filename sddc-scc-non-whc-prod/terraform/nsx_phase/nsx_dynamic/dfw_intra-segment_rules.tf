/*========================================

###########################################################################
###########################################################################
###                                                                     ###
###             INTRA-SEGMENT RULES - NOT MIGRATED FROM SCC             ###
###                                                                     ###
###########################################################################
###########################################################################

========================================*/

resource "nsxt_policy_security_policy" "intra-segment" {
  display_name    = "intra-segment"
  description     = "Firewall section for intra-segment"
  category        = var.category
  stateful        = var.stateful
  sequence_number = "1"
  domain          = "cgw"
  rule {
    display_name       = "10.120.100.0/24 to 10.120.100.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-100-0s24v262.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-100-0s24v262.path]
  }
  rule {
    display_name       = "10.120.101.0/27 to 10.120.101.0/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-101-0s27v263.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-101-0s27v263.path]
  }
  rule {
    display_name       = "10.120.102.0/24 to 10.120.102.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-102-0s24v264.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-102-0s24v264.path]
  }
  rule {
    display_name       = "10.120.103.0/29 to 10.120.103.0/29"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-103-0s29.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-103-0s29.path]
  }
  rule {
    display_name       = "10.120.129.0/24 to 10.120.129.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-129-0s24v301.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-129-0s24v301.path]
  }
  rule {
    display_name       = "10.120.131.0/24 to 10.120.131.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-131-0s24v303.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-131-0s24v303.path]
  }
  rule {
    display_name       = "10.120.132.0/24 to 10.120.132.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-132-0s24v304.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-132-0s24v304.path]
  }
  rule {
    display_name       = "10.120.136.0/24 to 10.120.136.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-136-0s24v309.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-136-0s24v309.path]
  }
  rule {
    display_name       = "10.120.137.0/24 to 10.120.137.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-137-0s24v310.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-137-0s24v310.path]
  }
  rule {
    display_name       = "10.120.139.0/27 to 10.120.139.0/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-139-0s27.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-139-0s27.path]
  }
  rule {
    display_name       = "10.120.140.0/24 to 10.120.140.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-140-0s24v320.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-140-0s24v320.path]
  }
  rule {
    display_name       = "10.120.141.0/24 to 10.120.141.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-141-0s24v321.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-141-0s24v321.path]
  }
  rule {
    display_name       = "10.120.143.66/27 to 10.120.143.66/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-143-64s27v334.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-143-64s27v334.path]
  }
  rule {
    display_name       = "10.120.145.0/24 to 10.120.145.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-145-0s24v341.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-145-0s24v341.path]
  }
  rule {
    display_name       = "10.120.146.0/24 to 10.120.146.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-146-0s24v342.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-146-0s24v342.path]
  }
  rule {
    display_name       = "10.120.148.0/24 to 10.120.148.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-148-0s24v344.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-148-0s24v344.path]
  }
  rule {
    display_name       = "10.120.149.0/24 to 10.120.149.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-149-0s24v345.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-149-0s24v345.path]
  }
  rule {
    display_name       = "10.120.151.0/24 to 10.120.151.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-151-0s24v347.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-151-0s24v347.path]
  }
  rule {
    display_name       = "10.120.152.0/24 to 10.120.152.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-152-0s24v348.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-152-0s24v348.path]
  }
  rule {
    display_name       = "10.120.153.0/24 to 10.120.153.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-153-0s24v349.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-153-0s24v349.path]
  }
  rule {
    display_name       = "10.120.159.96/27 to 10.120.159.96/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-159-96s27v365.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-159-96s27v365.path]
  }
  rule {
    display_name       = "10.120.161.224/27 to 10.120.161.224/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-161-224s27v385.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-161-224s27v385.path]
  }
  rule {
    display_name       = "10.120.162.0/24 to 10.120.162.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-162-0s24v398.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-162-0s24v398.path]
  }
  rule {
    display_name       = "10.120.163.0/24 to 10.120.163.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-163-0s24v399.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-163-0s24v399.path]
  }
  rule {
    display_name       = "10.120.170.0/25 to 10.120.170.0/25"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-170-0s25v450.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-170-0s25v450.path]
  }
  rule {
    display_name       = "10.120.170.128/25 to 10.120.170.128/25"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-170-128s25v451.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-170-128s25v451.path]
  }
  rule {
    display_name       = "10.120.172.0/24 to 10.120.172.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-172-0s24v453.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-172-0s24v453.path]
  }
  rule {
    display_name       = "10.120.173.0/25 to 10.120.173.0/25"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-173-0s25v460.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-173-0s25v460.path]
  }
  rule {
    display_name       = "10.120.173.128/25 to 10.120.173.128/25"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-173-128s25v461.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-173-128s25v461.path]
  }
  rule {
    display_name       = "10.120.177.0/25 to 10.120.177.0/25"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-177-0s25v480.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-177-0s25v480.path]
  }
  rule {
    display_name       = "10.120.180.0/25 to 10.120.180.0/25"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-180-0s25v485.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-180-0s25v485.path]
  }
  rule {
    display_name       = "10.120.180.128/25 to 10.120.180.128/25"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-180-128s25v486.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-180-128s25v486.path]
  }
  rule {
    display_name       = "10.120.192.128/27 to 10.120.192.128/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-192-128s27.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-192-128s27.path]
  }
  rule {
    display_name       = "10.120.192.160/29 to 10.120.192.160/29"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-192-160s29v565.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-192-160s29v565.path]
  }
  rule {
    display_name       = "10.120.192.168/29 to 10.120.192.168/29"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-192-168s29.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-192-168s29.path]
  }
  rule {
    display_name       = "10.120.193.224/27 to 10.120.193.224/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-193-224s27v575.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-193-224s27v575.path]
  }
  rule {
    display_name       = "10.120.194.0/26 to 10.120.194.0/26"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-194-0s26v576.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-194-0s26v576.path]
  }
  rule {
    display_name       = "10.120.194.192/26 to 10.120.194.192/26"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "38"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-194-192s26v579.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-194-192s26v579.path]
  }
  rule {
    display_name       = "10.120.194.64/26 to 10.120.194.64/26"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "39"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-194-64s26v577.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-194-64s26v577.path]
  }
  rule {
    display_name       = "10.120.195.0/24 to 10.120.195.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "40"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-195-0s24v580.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-195-0s24v580.path]
  }
  rule {
    display_name       = "10.120.196.0/24 to 10.120.196.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "41"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-196-0s24v581.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-196-0s24v581.path]
  }
  rule {
    display_name       = "10.120.208.0/24 to 10.120.208.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "42"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-208-0s24v650.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-208-0s24v650.path]
  }
  rule {
    display_name       = "10.120.216.0/21 to 10.120.216.0/21"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "43"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-216-0s21v397.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-216-0s21v397.path]
  }
  rule {
    display_name       = "10.120.254.208/29 to 10.120.254.208/29"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "44"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-254-208s29v989.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-254-208s29v989.path]
  }
  rule {
    display_name       = "10.120.32.128/27 to 10.120.32.128/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "45"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-32-128s27v104.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-32-128s27v104.path]
  }
  rule {
    display_name       = "10.120.32.96/27 to 10.120.32.96/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "46"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-32-96s27v103.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-32-96s27v103.path]
  }
  rule {
    display_name       = "10.120.33.0/29 to 10.120.33.0/29"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "47"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-33-0s29v109.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-33-0s29v109.path]
  }
  rule {
    display_name       = "10.120.33.160/27 to 10.120.33.160/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "48"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-33-160s27v115.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-33-160s27v115.path]
  }
  rule {
    display_name       = "10.120.36.0/24 to 10.120.36.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "49"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-36-0s24.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-36-0s24.path]
  }
  rule {
    display_name       = "10.120.37.0/24 to 10.120.37.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "50"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-37-0s24v121.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-37-0s24v121.path]
  }
  rule {
    display_name       = "10.120.38.0/24 to 10.120.38.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "51"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-38-0s24v122.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-38-0s24v122.path]
  }
  rule {
    display_name       = "10.120.39.0/24 to 10.120.39.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "52"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-39-0s24v123.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-39-0s24v123.path]
  }
  rule {
    display_name       = "10.120.43.0/24 to 10.120.43.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "53"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-43-0s24v124.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-43-0s24v124.path]
  }
  rule {
    display_name       = "10.120.44.0/23 to 10.120.44.0/23"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "54"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-44-0s23v134.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-44-0s23v134.path]
  }
  rule {
    display_name       = "10.120.46.0/25 to 10.120.46.0/25"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "55"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-46-0s25v140.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-46-0s25v140.path]
  }
  rule {
    display_name       = "10.120.50.0/24 to 10.120.50.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "56"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-50-0s24v160.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-50-0s24v160.path]
  }
  rule {
    display_name       = "10.120.64.128/27 to 10.120.64.128/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "57"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-64-128s27v204.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-64-128s27v204.path]
  }
  rule {
    display_name       = "10.120.64.160/27 to 10.120.64.160/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "58"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-64-160s27v205.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-64-160s27v205.path]
  }
  rule {
    display_name       = "10.120.65.128/27 to 10.120.65.128/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "59"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-65-128s27v235.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-65-128s27v235.path]
  }
  rule {
    display_name       = "10.120.65.64/27 to 10.120.65.64/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "60"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-65-64s27v232.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-65-64s27v232.path]
  }
  rule {
    display_name       = "10.120.65.96/27 to 10.120.65.96/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "61"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-65-96s27v234.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-65-96s27v234.path]
  }
  rule {
    display_name       = "10.120.66.0/24 to 10.120.66.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "62"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-66-0s24v210.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-66-0s24v210.path]
  }
  rule {
    display_name       = "10.120.67.0/24 to 10.120.67.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "63"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-67-0s24v211.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-67-0s24v211.path]
  }
  rule {
    display_name       = "10.120.69.192/27 to 10.120.69.192/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "64"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-69-192s27v219.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-69-192s27v219.path]
  }
  rule {
    display_name       = "10.120.69.224/27 to 10.120.69.224/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "65"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-69-224s27v218.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-69-224s27v218.path]
  }
  rule {
    display_name       = "10.120.69.96/27 to 10.120.69.96/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "66"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-69-96s27v216.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-69-96s27v216.path]
  }
  rule {
    display_name       = "10.120.70.0/27 to 10.120.70.0/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "67"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-70-0s27v223.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-70-0s27v223.path]
  }
  rule {
    display_name       = "10.120.71.0/24 to 10.120.71.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "68"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-71-0s24.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-71-0s24.path]
  }
  rule {
    display_name       = "10.120.72.0/24 to 10.120.72.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "69"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-72-0s24v222.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-72-0s24v222.path]
  }
  rule {
    display_name       = "10.120.74.0/23 to 10.120.74.0/23"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "70"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-74-0s23v231.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-74-0s23v231.path]
  }
  rule {
    display_name       = "10.120.76.0/24 to 10.120.76.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "71"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-76-0s24v233.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-76-0s24v233.path]
  }
  rule {
    display_name       = "10.120.98.0/24 to 10.120.98.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "72"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-98-0s24v260.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-98-0s24v260.path]
  }
  rule {
    display_name       = "10.120.99.0/24 to 10.120.99.0/24"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "73"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-99-0s24v261.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-99-0s24v261.path]
  }
  rule {
    display_name       = "10.156.4.0/25 to 10.156.4.0/25"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "74"
    source_groups      = [nsxt_policy_group.intra-segment_10-156-4-0s25.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-156-4-0s25.path]
  }
  rule {
    display_name       = "10.156.5.128/27 to 10.156.5.128/27"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "75"
    source_groups      = [nsxt_policy_group.intra-segment_10-156-5-128s27.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-156-5-128s27.path]
  }
  rule {
    display_name       = "10.120.33.192/27 to 10.120.33.192/27"
    description        = "Change ref: CHG0149147"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "76"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-33-192s26.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-33-192s26.path]
  }
  rule {
    display_name       = "10.120.194.128/27 to 10.120.194.128/27"
    description        = "Change ref: CHG0149147"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "77"
    source_groups      = [nsxt_policy_group.intra-segment_10-120-194-128s27.path]
    destination_groups = [nsxt_policy_group.intra-segment_10-120-194-128s27.path]
  }
}
